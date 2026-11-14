//! Autotestes (fase 6) dos exports de energia e de I/O que os drivers de
//! barramento importam: pedidos térmicos sobre um dispositivo sintético
//! que responde a GUID_THERMAL_COOLING_INTERFACE, o callback de vigia de
//! DRIPS do PoFx, PoSetHiberRange, ZwInitiatePowerAction, o grafo de
//! dependências, IoRequestDeviceRemovalForReset, IoAssignResources e
//! IoWMIExecuteMethod, cada um chamado pelo nome.
//!
//! Os valores esperados vêm das instruções de cada rotina no ntoskrnl
//! 19041 (status, campos e a ordem das chamadas à interface do driver).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::phase6::call_export;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{DeviceObject, DevobjExtension, DriverObject, IoStackLocation, Irp};
use crate::ntos::io::{device_removal, io_manager};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

type Assert = fn(bool, &str);

const STATUS_UNSUCCESSFUL: u64 = 0xC000_0001;
const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
const STATUS_OBJECT_TYPE_MISMATCH: u64 = 0xC000_0024;
const STATUS_NOT_SUPPORTED: u64 = 0xC000_00BB;
const STATUS_TOO_LATE: u64 = 0xC000_0189;

/// As chamadas que o driver sintético recebeu: (rotina, argumento).
static COOLING_CALLS: SpinLock<Vec<(u8, u64)>> = SpinLock::new(Vec::new());
static INTERFACE_REFERENCES: AtomicU64 = AtomicU64::new(0);
/// 0 = responde a interface; senão o status de falha do QUERY_INTERFACE.
static QUERY_FAILURE: AtomicU64 = AtomicU64::new(0);

extern "win64" fn active_cooling(_context: u64, engaged: u8) {
    COOLING_CALLS.lock().push((b'A', engaged as u64));
}

extern "win64" fn passive_cooling(_context: u64, percentage: u8) {
    COOLING_CALLS.lock().push((b'P', percentage as u64));
}

extern "win64" fn interface_reference(_context: u64) {
    INTERFACE_REFERENCES.fetch_add(1, Ordering::SeqCst);
}

extern "win64" fn interface_dereference(_context: u64) {
    INTERFACE_REFERENCES.fetch_sub(1, Ordering::SeqCst);
}

/// IRP_MJ_PNP do dispositivo sintético: QUERY_INTERFACE preenche o
/// THERMAL_COOLING_INTERFACE (ou falha com o status pedido).
extern "win64" fn cooling_dispatch(_device: u64, packet: u64) -> u64 {
    // SAFETY: o IRP que o I/O Manager entregou ao despacho.
    let irp = unsafe { Irp::at(packet) };
    let location = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
    let failure = QUERY_FAILURE.load(Ordering::SeqCst);
    let status = if location.minor_function.get() != 8 {
        STATUS_NOT_SUPPORTED as u32
    } else if failure != 0 {
        failure as u32
    } else {
        let interface = location.parameters.query_interface.interface.get();
        guest::write16(interface, 0x38);
        guest::write16(interface + 2, 1);
        guest::write64(interface + 8, 0xC0C0);
        guest::write64(interface + 0x10, interface_reference as extern "win64" fn(u64) as usize as u64);
        guest::write64(interface + 0x18, interface_dereference as extern "win64" fn(u64) as usize as u64);
        guest::write32(interface + 0x20, 0);
        guest::write64(interface + 0x28, active_cooling as extern "win64" fn(u64, u8) as usize as u64);
        guest::write64(interface + 0x30, passive_cooling as extern "win64" fn(u64, u8) as usize as u64);
        INTERFACE_REFERENCES.fetch_add(1, Ordering::SeqCst);
        0
    };
    irp.io_status.status.set(status as i32);
    io_manager::iof_complete_request(packet);
    status as u64
}

/// Driver e dispositivo sintéticos (DEVOBJ_EXTENSION inclusa).
struct Synthetic {
    driver: u64,
    device: u64,
    extension: u64,
}

fn synthetic_device() -> Synthetic {
    let (driver, device, extension) = (guest::alloc_bytes(DriverObject::SIZE), guest::alloc_bytes(DeviceObject::SIZE), guest::alloc_bytes(DevobjExtension::SIZE));
    let routine = cooling_dispatch as extern "win64" fn(u64, u64) -> u64 as usize as u64;
    // SAFETY: blocos zerados recém-alocados com o tamanho de cada tipo.
    let (driver_object, device_object) = unsafe { (DriverObject::at(driver), DeviceObject::at(device)) };
    driver_object.major_function[0x1B].set(routine);
    device_object.driver_object.set(driver);
    device_object.stack_size.set(1);
    device_object.device_object_extension.set(extension);
    Synthetic { driver, device, extension }
}

fn release(synthetic: Synthetic) {
    for block in [synthetic.driver, synthetic.device, synthetic.extension] {
        guest::free_bytes(block);
    }
}

fn status(name: &str, arguments: &[u64]) -> u64 {
    call_export(name, arguments).map_or(u64::MAX, |value| value as u32 as u64)
}

fn thermal_exports(assert: Assert) {
    let target = synthetic_device();
    let block = guest::alloc_bytes(0x200);
    let (output, context, second_output) = (block, block + 0x20, block + 0x10);
    // COUNTED_REASON_CONTEXT simples: Version 0, SIMPLE_STRING, "fan".
    guest::write32(context, 0);
    guest::write32(context + 4, 1);
    guest::write16(context + 8, 6);
    guest::write16(context + 0xA, 6);
    guest::write64(context + 0x10, block + 0x80);
    guest::write_bytes(block + 0x80, &[b'f', 0, b'a', 0, b'n', 0]);
    COOLING_CALLS.lock().clear();
    INTERFACE_REFERENCES.store(0, Ordering::SeqCst);
    QUERY_FAILURE.store(0, Ordering::SeqCst);
    let invalid = [status("PoCreateThermalRequest", &[output, 0, target.device, context, 0]), status("PoCreateThermalRequest", &[output, target.device, 0, context, 0]), status("PoCreateThermalRequest", &[output, target.device, target.device, 0, 0])];
    guest::write32(context, 1);
    let bad_version = status("PoCreateThermalRequest", &[output, target.device, target.device, context, 0]);
    guest::write32(context, 0);
    let created = status("PoCreateThermalRequest", &[output, target.device, target.device, context, 0]);
    let request = guest::read64(output);
    let supports = [call_export("PoGetThermalRequestSupport", &[request, 0]), call_export("PoGetThermalRequestSupport", &[request, 1]), call_export("PoGetThermalRequestSupport", &[request, 2])];
    assert(invalid == [STATUS_INVALID_PARAMETER; 3] && bad_version == STATUS_INVALID_PARAMETER && created == 0 && request != 0 && INTERFACE_REFERENCES.load(Ordering::SeqCst) == 1 && supports == [Some(1), Some(1), Some(0)], "thermal: PoCreateThermalRequest pede a interface ao alvo e PoGetThermalRequestSupport");
    // Agregado: mínimo dos percentuais, OU dos ativos; só as mudanças chamam.
    let _ = status("PoCreateThermalRequest", &[second_output, target.device, target.device, context, 0]);
    let second = guest::read64(second_output);
    let steps = [
        status("PoSetThermalPassiveCooling", &[request, 60]),
        status("PoSetThermalPassiveCooling", &[second, 80]),
        status("PoSetThermalPassiveCooling", &[second, 40]),
        status("PoSetThermalActiveCooling", &[request, 1]),
        status("PoSetThermalActiveCooling", &[second, 1]),
        status("PoSetThermalActiveCooling", &[request, 0]),
        status("PoSetThermalPassiveCooling", &[request, 101]),
    ];
    let calls_before_delete = COOLING_CALLS.lock().clone();
    let _ = call_export("PoDeleteThermalRequest", &[second]);
    let calls_after_second = COOLING_CALLS.lock().clone();
    let references_with_one = INTERFACE_REFERENCES.load(Ordering::SeqCst);
    let _ = call_export("PoDeleteThermalRequest", &[request]);
    assert(steps == [0, 0, 0, 0, 0, 0, STATUS_INVALID_PARAMETER] && calls_before_delete == [(b'P', 60), (b'P', 40), (b'A', 1)] && calls_after_second == [(b'P', 60), (b'P', 40), (b'A', 1), (b'P', 60), (b'A', 0)] && references_with_one == 1 && INTERFACE_REFERENCES.load(Ordering::SeqCst) == 0, "thermal: agregado dos pedidos, chamadas so nas mudancas e a interface devolvida no ultimo pedido");
    QUERY_FAILURE.store(STATUS_NOT_SUPPORTED, Ordering::SeqCst);
    let refused = status("PoCreateThermalRequest", &[output, target.device, target.device, context, 0]);
    QUERY_FAILURE.store(0, Ordering::SeqCst);
    assert(refused == STATUS_NOT_SUPPORTED && guest::read64(output) == 0, "thermal: alvo sem a interface recusa o pedido com o status do driver");
    guest::free_bytes(block);
    release(target);
}

fn power_exports(assert: Assert) {
    let block = guest::alloc_bytes(0x200);
    // PoFx: um PO_FX_DEVICE_V1 sem componentes e o vigia de DRIPS.
    let (description, handle_out) = (block, block + 0x100);
    guest::write32(description, 1);
    let registered = status("PoFxRegisterDevice", &[block + 0x180, description, handle_out]);
    let handle = guest::read64(handle_out);
    let _ = call_export("PoFxRegisterDripsWatchdogCallback", &[handle, 0x7777, 1, 0x8888]);
    let fields = (guest::read64(handle + 0xA8), guest::read64(handle + 0x360), guest::read32(handle + 0x338) & 8);
    let _ = call_export("PoFxUnregisterDevice", &[handle]);
    assert(registered == 0 && fields == (0x7777, 0x8888, 8), "power: PoFxRegisterDripsWatchdogCallback grava o callback, o driver e a bandeira dos filhos");
    // Mapa de hibernação já fechado: nada a fazer.
    let map = block + 0x40;
    guest::write32(map + 0xB8, 9);
    let _ = call_export("PoSetHiberRange", &[map, 0x10000, block, 0x1000, 0]);
    assert(guest::read32(map + 0xB8) == 9, "power: PoSetHiberRange com o mapa fechado nao faz nada");
    let actions = [
        status("ZwInitiatePowerAction", &[8, 1, 0, 0]),
        status("ZwInitiatePowerAction", &[0, 8, 0, 0]),
        status("ZwInitiatePowerAction", &[0, 1, 1 << 28, 0]),
        status("ZwInitiatePowerAction", &[2, 5, 0, 0]),
        status("ZwInitiatePowerAction", &[0, 1, 0x40, 0]),
        status("ZwInitiatePowerAction", &[0, 1, 0, 0]),
        status("ZwInitiatePowerAction", &[5, 4, 0xC000_0004, 0]),
    ];
    assert(actions == [STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER, 0, STATUS_NOT_SUPPORTED] && crate::ntos::init::exports::lookup("ntoskrnl.exe", "PoShutdownBugCheck").is_some(), "power: ZwInitiatePowerAction valida como o NtInitiatePowerAction; o PoShutdownBugCheck cai no bugcheck");
    guest::free_bytes(block);
}

fn dependency_exports(assert: Assert) {
    let (a, b, c) = (synthetic_device(), synthetic_device(), synthetic_device());
    let block = guest::alloc_bytes(0x100);
    let (path, flags, name, other) = (block, block + 4, block + 0x10, block + 0x20);
    let unicode = |at: u64, text: &str, buffer: u64| {
        let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        guest::write_bytes(buffer, &units);
        guest::write16(at, units.len() as u16);
        guest::write16(at + 2, units.len() as u16);
        guest::write64(at + 8, buffer);
    };
    unicode(name, "ACPI\\PNP0C0A\\1", block + 0x40);
    unicode(other, "acpi\\pnp0c0a\\1", block + 0x80);
    let test = |dependent: u64, provider: u64| -> (u64, u32, u32) {
        guest::write32(path, 0x55);
        guest::write32(flags, 0x55);
        (status("IoTestDependency", &[dependent, provider, path, flags]), guest::read32(path), guest::read32(flags))
    };
    let invalid = [status("IoSetDependency", &[0, b.device, 1]), status("IoSetDependency", &[a.device, b.device, 0]), status("IoSetDependency", &[a.device, b.device, 4]), status("IoSetDependency", &[a.device, a.device, 1])];
    let none = test(a.device, b.device);
    let direct = status("IoSetDependency", &[a.device, b.device, 1]);
    let merged = status("IoSetDependency", &[a.device, b.device, 2]);
    let reverse = status("IoSetDependency", &[b.device, a.device, 1]);
    let chained = status("IoSetDependency", &[b.device, c.device, 2]);
    assert(invalid == [STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL] && none == (0, 0, 0) && direct == 0 && merged == 0 && reverse == STATUS_UNSUCCESSFUL && chained == 0 && guest::read64(a.extension + 0x50) != 0, "dependency: IoSetDependency valida flags, recusa a aresta inversa e junta pedidos");
    let paths = [test(a.device, b.device), test(a.device, c.device), test(c.device, a.device), test(b.device, a.device)];
    assert(paths == [(0, 1, 3), (0, 2, 3), (0, 0, 0), (0, 0, 0)] && status("IoTestDependency", &[a.device, a.device, path, flags]) == STATUS_INVALID_PARAMETER, "dependency: IoTestDependency direta, indireta e sem caminho");
    // Reserva por nome e resolução para um dispositivo novo.
    let d = synthetic_device();
    let reserved = status("IoReserveDependency", &[c.device, name, 1]);
    let before = test(c.device, d.device);
    let resolved = status("IoResolveDependency", &[other, d.device]);
    let after = test(c.device, d.device);
    let same = status("IoResolveDependency", &[name, d.device]);
    assert(reserved == 0 && before == (0, 0, 0) && resolved == 0 && after == (0, 1, 1) && same == 0, "dependency: IoReserveDependency por nome e IoResolveDependency liga o nome ao provedor");
    // Duplicação: os dependentes de B ganham aresta para E.
    let e = synthetic_device();
    let duplicated = status("IoDuplicateDependency", &[b.device, e.device]);
    let copied = test(a.device, e.device);
    let empty = status("IoDuplicateDependency", &[e.device, c.device]);
    assert(duplicated == 0 && copied == (0, 1, 3) && empty == 0 && status("IoDuplicateDependency", &[0, e.device]) == STATUS_INVALID_PARAMETER, "dependency: IoDuplicateDependency copia os pedidos dos dependentes");
    guest::free_bytes(block);
    // Os nós continuam no grafo (o NT os solta na remoção do dispositivo).
    for synthetic in [a, b, c, d, e] {
        core::mem::forget(synthetic);
    }
}

fn io_support_exports(assert: Assert) {
    let target = synthetic_device();
    let block = guest::alloc_bytes(0x100);
    // IoRequestDeviceRemovalForReset: o PnP do OpenNT não aceita o evento.
    let pdo = io_manager::devices().into_iter().map(|(_, entry)| entry.native_device).find(|&device| device_removal::has_device_node(device)).unwrap_or(0);
    assert(pdo != 0 && status("IoRequestDeviceRemovalForReset", &[pdo, 0]) == STATUS_TOO_LATE, "io: IoRequestDeviceRemovalForReset sem processamento de eventos de dispositivo-alvo");
    // IoAssignResources sem pedido: liberação, *Allocated NULL.
    let allocated = block;
    guest::write64(allocated, 0x5555);
    let released = status("IoAssignResources", &[0, 0, target.driver, target.device, 0, allocated]);
    guest::write64(allocated, 0x5555);
    // Lista com AlternativeLists = 0 vale como nenhuma.
    let requirements = block + 0x20;
    guest::write32(requirements, 0x20);
    guest::write32(requirements + 0x1C, 0);
    let empty = status("IoAssignResources", &[0, 0, target.driver, target.device, requirements, allocated]);
    assert(released == 0 && empty == 0 && guest::read64(allocated) == 0, "io: IoAssignResources sem pedido libera e devolve NULL");
    // IoWMIExecuteMethod sem objeto e com um objeto que não é de GUID WMI.
    let (size, buffer, instance) = (block + 0x40, block + 0x60, block + 0x48);
    guest::write32(size, 8);
    guest::write16(instance, 0);
    guest::write16(instance + 2, 0);
    guest::write64(instance + 8, 0);
    let no_object = status("IoWMIExecuteMethod", &[0, instance, 1, 4, size, buffer]);
    let wrong_object = status("IoWMIExecuteMethod", &[target.device, instance, 1, 4, size, buffer]);
    assert(no_object == STATUS_INVALID_HANDLE && wrong_object == STATUS_OBJECT_TYPE_MISMATCH && guest::read32(size) == 8, "io: IoWMIExecuteMethod sem bloco de dados de GUID WMI");
    guest::free_bytes(block);
    release(target);
}

pub fn run(assert: Assert) {
    thermal_exports(assert);
    power_exports(assert);
    dependency_exports(assert);
    io_support_exports(assert);
}
