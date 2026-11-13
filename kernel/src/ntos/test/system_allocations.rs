//! Autoteste das alocações do kernel na metade de sistema.
//!
//! Roda no fim da fase 6, com os drivers reais do boot já carregados: toda
//! memória que o kernel entrega a um driver fica em MmSystemRangeStart ou
//! acima, como no NT — o que os drivers reais conferem contra
//! MmUserProbeAddress/MmSystemRangeStart para separar ponteiros de kernel de
//! ponteiros de usuário. Confere a arena dos convidados e o heap do kernel
//! (janela do heap, com a tradução linear para os frames do heap), o pool
//! (ExAllocatePoolWithTag, ExAllocatePool2), IRPs e MDLs do I/O Manager e
//! os DRIVER_OBJECTs e DEVICE_OBJECTs vivos, inclusive os criados pelos
//! drivers reais carregados na janela de imagens de sistema. Confere também
//! o próprio kernel: uma rotina, uma variável estática e a pilha corrente
//! ficam na metade de sistema, e o ntoskrnl registrado começa na ImageBase
//! em que ele foi ligado.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map::{self as map, KERNEL_HEAP_BASE, KERNEL_HEAP_TOP, SYSTEM_IMAGE_BASE, SYSTEM_IMAGE_TOP};
use crate::ntos::mm::{loaded_images, paging, system_info};
use crate::ntos::ob::object_manager;

type Assert = fn(bool, &str);
type CallExport = fn(&str, &[u64]) -> Option<u64>;

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: objetos vivos do kernel (DRIVER_OBJECT, DEVICE_OBJECT, IRP).
    unsafe { T::at(address) }
}

/// Bloco da janela do heap cuja VA traduz pela tabela real para o frame
/// que a janela promete.
fn in_heap_window(address: u64) -> bool {
    address >= KERNEL_HEAP_BASE && address < KERNEL_HEAP_TOP && paging::translate(address) == map::kernel_heap_physical(address)
}

/// DRIVER_OBJECT e os DEVICE_OBJECTs (com extensões) da sua lista.
struct DriverObjects {
    driver: u64,
    real: bool,
    devices: Vec<(u64, u64)>,
}

fn driver_objects() -> Vec<DriverObjects> {
    let mut drivers = Vec::new();
    for (id, _) in object_manager::namespace_entries() {
        let Some(node) = object_manager::node(id) else { continue };
        let driver = node.data.as_ref().map_or(0, |data| data.native_pointer);
        if node.type_name != "Driver" || driver == 0 {
            continue;
        }
        let object = at::<nt::DriverObject>(driver);
        let start = object.driver_start.get();
        let mut devices = Vec::new();
        let mut device = object.device_object.get();
        while device != 0 && devices.len() < 256 {
            devices.push((device, at::<nt::DeviceObject>(device).device_extension.get()));
            device = at::<nt::DeviceObject>(device).next_device.get();
        }
        drivers.push(DriverObjects { driver, real: (SYSTEM_IMAGE_BASE..SYSTEM_IMAGE_TOP).contains(&start), devices });
    }
    drivers
}

pub fn run(assert: Assert, call_export: CallExport) {
    let system_range_start = guest::read64(system_info::system_range_start_cell());
    let system = |address: u64| address != 0 && address >= system_range_start;
    assert(system_range_start == 0xFFFF_8000_0000_0000, "sysalloc: MmSystemRangeStart = 0xFFFF800000000000");

    // O kernel executa na sua VA de sistema: código, dados estáticos e pilha.
    static IMAGE_DATA: AtomicU64 = AtomicU64::new(0x4F70_656E_4E54_0001);
    let routine = run as fn(Assert, CallExport) as usize as u64;
    let data = &IMAGE_DATA as *const AtomicU64 as u64;
    let stack = &system_range_start as *const u64 as u64;
    let kernel = loaded_images::kernel();
    let in_kernel = |address: u64| kernel.as_ref().is_some_and(|image| address >= image.image_base && address - image.image_base < image.size_of_image);
    assert(
        kernel.as_ref().is_some_and(|image| image.image_base == map::KERNEL_VIRTUAL_BASE) && system(routine) && system(data) && in_kernel(routine) && in_kernel(data),
        "sysalloc: rotina e estatica do kernel no ntoskrnl em KERNEL_VIRTUAL_BASE, acima de MmSystemRangeStart",
    );
    assert(IMAGE_DATA.load(Ordering::Relaxed) == 0x4F70_656E_4E54_0001 && system(stack) && paging::translate(data) != 0, "sysalloc: pilha corrente e dados da imagem pela VA de sistema");

    // Arena dos convidados e heap do kernel: VAs da janela do heap.
    let (bytes, page, raw) = (guest::alloc_bytes(0x40), guest::alloc_page(), guest::alloc_raw(0x30));
    let boxed = Box::new([0u64; 4]);
    let heap = boxed.as_ptr() as u64;
    assert(
        [bytes, page, raw, heap].iter().all(|&address| system(address) && in_heap_window(address)) && page & 0xFFF == 0 && guest::in_arena(bytes) && !guest::in_arena(heap),
        "sysalloc: arena e heap do kernel na janela do heap, acima de MmSystemRangeStart",
    );
    guest::write64(bytes, 0x0123_4567_89AB_CDEF);
    assert(crate::hal::physical::read64(map::kernel_heap_physical(bytes)) == 0x0123_4567_89AB_CDEF, "sysalloc: VA da arena e frame do heap sao a mesma memoria");
    drop(boxed);
    guest::free_bytes(bytes);
    guest::free_bytes(page);
    guest::free_bytes(raw);

    // Pool pelos exports, como um driver pede.
    let tag = u32::from_le_bytes(*b"HiH2") as u64;
    let nonpaged = call_export("ExAllocatePoolWithTag", &[0, 0x80, tag]).unwrap_or(0);
    let paged = call_export("ExAllocatePoolWithTag", &[1, 0x80, tag]).unwrap_or(0);
    let modern = call_export("ExAllocatePool2", &[0x40, 0x80, tag]).unwrap_or(0);
    assert(system(nonpaged) && system(paged) && system(modern) && guest::in_arena(modern), "sysalloc: ExAllocatePoolWithTag e ExAllocatePool2 acima de MmSystemRangeStart");
    for pointer in [nonpaged, paged, modern] {
        if pointer != 0 {
            call_export("ExFreePoolWithTag", &[pointer, tag]);
        }
    }

    // IRPs e MDLs do I/O Manager.
    let irp = call_export("IoAllocateIrp", &[4, 0]).unwrap_or(0);
    let buffer = guest::alloc_bytes(0x1000);
    let mdl = call_export("IoAllocateMdl", &[buffer, 0x1000, 0, 0, 0]).unwrap_or(0);
    assert(system(irp) && system(mdl) && at::<nt::Irp>(irp).type_.get() == 6, "sysalloc: IoAllocateIrp e IoAllocateMdl acima de MmSystemRangeStart");
    if mdl != 0 {
        call_export("IoFreeMdl", &[mdl]);
    }
    if irp != 0 {
        call_export("IoFreeIrp", &[irp]);
    }

    // DRIVER_OBJECTs e DEVICE_OBJECTs vivos; os dos drivers reais vêm de
    // IoCreateDevice chamado pelo próprio driver.
    let drivers = driver_objects();
    for driver in drivers.iter().filter(|driver| driver.real) {
        crate::debug_print!("[sysalloc] driver {:#x} com {} dispositivo(s), primeiro {:#x}", driver.driver, driver.devices.len(), driver.devices.first().map_or(0, |device| device.0));
    }
    assert(
        !drivers.is_empty() && drivers.iter().all(|driver| system(driver.driver) && driver.devices.iter().all(|&(device, extension)| system(device) && (extension == 0 || system(extension)))),
        "sysalloc: todo DRIVER_OBJECT e DEVICE_OBJECT acima de MmSystemRangeStart",
    );
    let real_device = drivers.iter().filter(|driver| driver.real).flat_map(|driver| driver.devices.iter()).map(|&(device, _)| device).next().unwrap_or(0);
    assert(real_device != 0 && in_heap_window(real_device), "sysalloc: DEVICE_OBJECT de driver real na janela do heap");

    // IRP montado para o dispositivo de um driver real.
    let status_block = buffer + 0x800;
    let flush = if real_device != 0 { call_export("IoBuildAsynchronousFsdRequest", &[9, real_device, 0, 0, 0, status_block]).unwrap_or(0) } else { 0 };
    assert(system(flush) && at::<nt::Irp>(flush).type_.get() == 6, "sysalloc: IRP de IoBuildAsynchronousFsdRequest para driver real acima de MmSystemRangeStart");
    if flush != 0 {
        call_export("IoFreeIrp", &[flush]);
    }
    guest::free_bytes(buffer);
}
