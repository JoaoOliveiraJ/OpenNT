//! CONTROLLER_OBJECT e o modelo StartIo.
//!
//! - `controller`: serializa um
//!   controlador de hardware compartilhado (o 8042 de teclado e mouse); com
//!   o controlador ocupado o pedido entra numa fila FIFO e IoFreeController
//!   dispara o próximo.
//! - `start_io`: I/O empacotado serializado
//!   por dispositivo na KDEVICE_QUEUE real do DEVICE_OBJECT, ordenada pela
//!   chave (os links ficam em IRP.Tail.Overlay.ListEntry).

pub mod controller {
    use alloc::collections::{BTreeMap, VecDeque};

    use crate::hal::amd64::native_call;
    use crate::rtl::SpinLock;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::{controller_object as co, device_object};

    #[derive(Clone, Copy)]
    struct Request {
        device: u64,
        routine: u64,
        context: u64,
        map_register_base: u64,
    }

    static QUEUES: SpinLock<BTreeMap<u64, VecDeque<Request>>> = SpinLock::new(BTreeMap::new());

    /// PDRIVER_CONTROL(DeviceObject, Device->CurrentIrp, MapRegisterBase,
    /// Context) -> IO_ALLOCATION_ACTION; diferente de zero libera.
    fn run(device: u64, routine: u64, map_register_base: u64, context: u64) -> u32 {
        let current = guest::read64(device + device_object::CURRENT_IRP);
        native_call::call(routine, &[device, current, map_register_base, context]) as u32
    }

    /// Dispara o próximo pedido quando o controlador libera.
    fn pump(controller: u64) {
        let Some(request) = QUEUES.lock().get_mut(&controller).and_then(VecDeque::pop_front) else { return };
        let action = run(request.device, request.routine, request.map_register_base, request.context);
        let queued = QUEUES.lock().get(&controller).map_or(0, VecDeque::len);
        guest::write32(controller + co::QUEUED, queued as u32);
        if action != 0 {
            guest::write8(controller + co::BUSY, 0);
            pump(controller);
        }
    }

    /// IoCreateController(SizeOfControllerExtension).
    pub fn create(extension_size: u32) -> u64 {
        let controller = guest::alloc_bytes(co::SIZE + extension_size as u64);
        guest::write32(controller + co::TYPE, co::TYPE_CONTROLLER as u32 | (co::SIZE as u32) << 16);
        guest::write32(controller + co::REFERENCE_COUNT, 1);
        guest::write8(controller + co::BUSY, 0);
        guest::write32(controller + co::QUEUED, 0);
        if extension_size > 0 {
            guest::write64(controller + co::CONTROLLER_EXTENSION, controller + co::SIZE);
        }
        QUEUES.lock().insert(controller, VecDeque::new());
        controller
    }

    /// IoDeleteController (o NT só permite com a fila vazia).
    pub fn delete(controller: u64) {
        QUEUES.lock().remove(&controller);
        guest::free_bytes(controller);
    }

    /// IoAllocateController: livre executa já; ocupado entra na fila FIFO.
    /// A fila guarda os 32 bits baixos dos ponteiros.
    pub fn allocate(controller: u64, device: u64, routine: u64, context: u64) {
        if guest::read8(controller + co::BUSY) == 0 {
            guest::write8(controller + co::BUSY, 1);
            if run(device, routine, 0, context) != 0 {
                guest::write8(controller + co::BUSY, 0);
                pump(controller);
            }
            return;
        }
        let queued = {
            let mut queues = QUEUES.lock();
            let queue = queues.entry(controller).or_default();
            queue.push_back(Request { device: device as u32 as u64, routine: routine as u32 as u64, context: context as u32 as u64, map_register_base: 0 });
            queue.len()
        };
        guest::write32(controller + co::QUEUED, queued as u32);
    }

    /// IoFreeController: libera e dispara o próximo da fila.
    pub fn free(controller: u64) {
        guest::write8(controller + co::BUSY, 0);
        pump(controller);
    }
}

pub mod start_io {
    use crate::hal::amd64::native_call;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::{device_object, driver_object, kdevice_queue as queue};

    /// IRP.Tail.Overlay.ListEntry e DriverContext[0] (a chave).
    const LIST_IN_IRP: u64 = 0x70;
    const KEY_IN_IRP: u64 = 0x80;

    fn head(device: u64) -> u64 {
        device + device_object::DEVICE_QUEUE
    }

    /// KeInitializeDeviceQueue na fila embutida do DEVICE_OBJECT.
    pub fn queue_initialize(device: u64) {
        let pointer = head(device);
        guest::write32(pointer + queue::TYPE, queue::TYPE_DEVICE_QUEUE as u32 | (queue::SIZE as u32) << 16);
        guest::write64(pointer + queue::LOCK, 0);
        guest::write8(pointer + queue::BUSY, 0);
        guest::write64(pointer + queue::ENTRY, pointer + queue::ENTRY);
        guest::write64(pointer + queue::ENTRY + 8, pointer + queue::ENTRY);
    }

    /// DriverStartIo(DeviceObject, Irp) do driver dono.
    fn call_start_io(device: u64, packet: u64) {
        let driver = guest::read64(device + device_object::DRIVER_OBJECT);
        let routine = guest::read64(driver + driver_object::DRIVER_START_IO);
        if routine != 0 {
            native_call::call(routine, &[device, packet, 0]);
        }
    }

    /// Drivers serializados pelo CONTROLLER_OBJECT nunca inicializam a fila,
    /// que nasce zerada: zeros contam como fila vazia.
    fn ensure_initialized(device: u64) {
        if guest::read64(head(device) + queue::ENTRY) == 0 {
            queue_initialize(device);
        }
    }

    /// IoStartPacket(Device, Irp, PULONG Key, CancelFunction): livre vira
    /// CurrentIrp e roda o StartIo; ocupado entra na fila ordenada pela chave.
    pub fn start_packet(device: u64, packet: u64, sort_key: u64, _cancel_routine: u64) {
        ensure_initialized(device);
        let pointer = head(device);
        let key = if sort_key != 0 { guest::read32(sort_key as u32 as u64) as u64 } else { 0xFFFF_FFFF };
        guest::write64(packet + KEY_IN_IRP, key);
        if guest::read64(device + device_object::CURRENT_IRP) == 0 && guest::read8(pointer + queue::BUSY) == 0 {
            guest::write8(pointer + queue::BUSY, 1);
            guest::write64(device + device_object::CURRENT_IRP, packet);
            call_start_io(device, packet);
            return;
        }
        let entry = packet + LIST_IN_IRP;
        let sentinel = pointer + queue::ENTRY;
        let mut cursor = guest::read64(sentinel);
        while cursor != sentinel {
            if guest::read64(cursor - LIST_IN_IRP + KEY_IN_IRP) > key {
                break;
            }
            cursor = guest::read64(cursor);
        }
        let blink = guest::read64(cursor + 8);
        guest::write64(entry, cursor);
        guest::write64(entry + 8, blink);
        guest::write64(blink, entry);
        guest::write64(cursor + 8, entry);
    }

    /// IoStartNextPacket: tira o primeiro da fila e dispara.
    pub fn start_next_packet(device: u64, _cancelable: bool) {
        ensure_initialized(device);
        let pointer = head(device);
        let sentinel = pointer + queue::ENTRY;
        let first = guest::read64(sentinel);
        guest::write64(device + device_object::CURRENT_IRP, 0);
        if first == sentinel {
            guest::write8(pointer + queue::BUSY, 0);
            return;
        }
        let flink = guest::read64(first);
        let blink = guest::read64(first + 8);
        guest::write64(blink, flink);
        guest::write64(flink + 8, blink);
        let next = first - LIST_IN_IRP;
        guest::write64(device + device_object::CURRENT_IRP, next);
        call_start_io(device, next);
    }

    /// IoSetStartIoAttributes: bits internos acima dos FILE_* baixos.
    pub fn set_start_io_attributes(device: u64, deferred_start_io: bool, serial_access: bool) {
        let mut attributes = guest::read32(device + device_object::CHARACTERISTICS) & 0xFFFF;
        if deferred_start_io {
            attributes |= 0x1_0000;
        }
        if serial_access {
            attributes |= 0x2_0000;
        }
        guest::write32(device + device_object::CHARACTERISTICS, attributes);
    }
}
