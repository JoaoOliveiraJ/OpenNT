//! CONTROLLER_OBJECT e o modelo StartIo.
//!
//! - `controller`: serializa um controlador de hardware compartilhado (o
//!   8042 de teclado e mouse) na DeviceWaitQueue (KDEVICE_QUEUE) do
//!   CONTROLLER_OBJECT, como o IoAllocateController do NT: com o controlador
//!   ocupado, a WAIT_CONTEXT_BLOCK do dispositivo (DeviceObject->Queue.Wcb)
//!   entra na fila FIFO e o IoFreeController dispara a próxima.
//! - `start_io`: I/O empacotado serializado por dispositivo na KDEVICE_QUEUE
//!   do DEVICE_OBJECT (DeviceObject->DeviceQueue), com o IRP ligado pela
//!   Tail.Overlay.DeviceQueueEntry e ordenado pela SortKey (o
//!   KeInsertByKeyDeviceQueue do IoStartPacket).
//!
//! A KDEVICE_QUEUE é a do NT (layout dos símbolos): lista em DeviceListHead,
//! KSPIN_LOCK em Lock e Busy; inserção e retirada acontecem com o Lock retido
//! em DISPATCH_LEVEL, então o teste-e-marca de Busy é atômico como no
//! KeInsertDeviceQueue.

/// Operações da KDEVICE_QUEUE (KeInitializeDeviceQueue, KeInsertDeviceQueue,
/// KeInsertByKeyDeviceQueue, KeRemoveDeviceQueue) sobre o layout do NT.
mod device_queue {
    use core::mem::offset_of;
    use core::sync::atomic::Ordering;

    use crate::hal::cpu;
    use crate::ntos::inc::types::{KdeviceQueue, KdeviceQueueEntry, ListEntry, NtStruct};
    use crate::ntos::ke::irql;

    /// DeviceQueueObject.
    const DEVICE_QUEUE_OBJECT: i16 = 0x14;

    /// Lock da fila retido em DISPATCH_LEVEL.
    struct Held<'a> {
        queue: &'a KdeviceQueue,
        previous: u8,
    }

    impl Drop for Held<'_> {
        fn drop(&mut self) {
            self.queue.lock.atomic().store(0, Ordering::Release);
            irql::lower_irql(self.previous as u64);
        }
    }

    fn lock(queue: &KdeviceQueue) -> Held<'_> {
        let previous = irql::raise_at_least(irql::DISPATCH_LEVEL);
        while queue.lock.atomic().compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            cpu::pause();
        }
        Held { queue, previous }
    }

    fn entry_at(address: u64) -> &'static KdeviceQueueEntry {
        // SAFETY: os elos da lista são KDEVICE_QUEUE_ENTRY inseridas por aqui.
        unsafe { KdeviceQueueEntry::at(address) }
    }

    fn link_at(address: u64) -> &'static ListEntry {
        // SAFETY: elo da lista (cabeça da fila ou DeviceListEntry de uma entrada).
        unsafe { ListEntry::at(address) }
    }

    /// Entrada que contém um elo (CONTAINING_RECORD).
    fn entry_of_link(link: u64) -> &'static KdeviceQueueEntry {
        entry_at(link - offset_of!(KdeviceQueueEntry, device_list_entry) as u64)
    }

    /// KeInitializeDeviceQueue.
    pub fn initialize(queue: &KdeviceQueue) {
        queue.type_.set(DEVICE_QUEUE_OBJECT);
        queue.size.set(KdeviceQueue::SIZE as i16);
        let head = queue.device_list_head.address();
        queue.device_list_head.flink.set(head);
        queue.device_list_head.blink.set(head);
        queue.lock.set(0);
        queue.busy.set(0);
    }

    /// Fila nunca inicializada (DEVICE_OBJECT zerado): zeros contam como vazia.
    pub fn ensure_initialized(queue: &KdeviceQueue) {
        if queue.device_list_head.flink.get() == 0 {
            initialize(queue);
        }
    }

    /// Insere antes de `next` (InsertTailList quando `next` é a cabeça).
    fn link_before(next: u64, entry: &KdeviceQueueEntry) {
        let link = &entry.device_list_entry;
        let previous = link_at(next).blink.get();
        link.flink.set(next);
        link.blink.set(previous);
        link_at(previous).flink.set(link.address());
        link_at(next).blink.set(link.address());
    }

    /// KeInsertDeviceQueue (`key = None`, no fim) / KeInsertByKeyDeviceQueue
    /// (depois de todas as entradas com SortKey <= key). Fila livre: marca
    /// Busy e devolve false (o chamador inicia já); ocupada: enfileira e
    /// devolve true.
    pub fn insert(queue: &KdeviceQueue, entry: &KdeviceQueueEntry, key: Option<u32>) -> bool {
        let _held = lock(queue);
        if queue.busy.get() == 0 {
            queue.busy.set(1);
            entry.inserted.set(0);
            return false;
        }
        let head = queue.device_list_head.address();
        let mut next = head;
        if let Some(key) = key {
            entry.sort_key.set(key);
            next = queue.device_list_head.flink.get();
            while next != head && entry_of_link(next).sort_key.get() <= key {
                next = link_at(next).flink.get();
            }
        }
        link_before(next, entry);
        entry.inserted.set(1);
        true
    }

    /// KeRemoveDeviceQueue: a primeira entrada, ou 0 com a fila vazia (que
    /// então deixa de estar ocupada).
    pub fn remove(queue: &KdeviceQueue) -> u64 {
        let _held = lock(queue);
        let head = queue.device_list_head.address();
        let first = queue.device_list_head.flink.get();
        if first == head {
            queue.busy.set(0);
            return 0;
        }
        let next = link_at(first).flink.get();
        queue.device_list_head.flink.set(next);
        link_at(next).blink.set(head);
        let entry = entry_of_link(first);
        entry.inserted.set(0);
        entry.address()
    }

    /// Entradas na fila (diagnóstico e testes).
    pub fn count(queue: &KdeviceQueue) -> usize {
        let _held = lock(queue);
        let head = queue.device_list_head.address();
        let mut count = 0;
        let mut link = queue.device_list_head.flink.get();
        while link != head && link != 0 {
            count += 1;
            link = link_at(link).flink.get();
        }
        count
    }
}

pub mod controller {
    use core::mem::offset_of;

    use super::device_queue;
    use crate::hal::amd64::native_call;
    use crate::ntos::inc::types::{ControllerObject, DeviceObject, DeviceObjectQueueView1, NtStruct, WaitContextBlock};
    use crate::ntos::mm::guest_memory as guest;

    /// IO_TYPE_CONTROLLER.
    const IO_TYPE_CONTROLLER: i16 = 2;
    /// IO_ALLOCATION_ACTION.DeallocateObject.
    const DEALLOCATE_OBJECT: u32 = 2;

    fn controller_at(controller: u64) -> &'static ControllerObject {
        // SAFETY: CONTROLLER_OBJECT criado por `create` e vivo até `delete`.
        unsafe { ControllerObject::at(controller) }
    }

    fn device_at(device: u64) -> &'static DeviceObject {
        // SAFETY: DEVICE_OBJECT vivo do chamador.
        unsafe { DeviceObject::at(device) }
    }

    /// DeviceObject->Queue.Wcb.
    fn wait_block(device: &DeviceObject) -> &WaitContextBlock {
        &device.queue.wcb
    }

    /// PDRIVER_CONTROL(DeviceObject, Device->CurrentIrp, MapRegisterBase=NULL,
    /// Context) com a rotina e o contexto da WAIT_CONTEXT_BLOCK.
    fn run(device: &DeviceObject) -> u32 {
        let block = wait_block(device);
        native_call::call(block.device_routine.get(), &[device.address(), device.current_irp.get(), 0, block.device_context.get()]) as u32
    }

    /// IoCreateController(SizeOfControllerExtension): extensão logo depois do
    /// objeto e DeviceWaitQueue inicializada.
    pub fn create(extension_size: u32) -> u64 {
        let address = guest::alloc_bytes(ControllerObject::SIZE + extension_size as u64);
        if address == 0 {
            return 0;
        }
        let controller = controller_at(address);
        controller.type_.set(IO_TYPE_CONTROLLER);
        controller.size.set((ControllerObject::SIZE + extension_size as u64) as i16);
        controller.controller_extension.set(address + ControllerObject::SIZE);
        device_queue::initialize(&controller.device_wait_queue);
        address
    }

    /// IoDeleteController (o NT só permite com a fila vazia).
    pub fn delete(controller: u64) {
        guest::free_bytes(controller);
    }

    /// IoAllocateController: Wcb.DeviceRoutine/DeviceContext e
    /// KeInsertDeviceQueue; livre, executa já e DeallocateObject libera.
    pub fn allocate(controller: u64, device: u64, routine: u64, context: u64) {
        let target = device_at(device);
        let block = wait_block(target);
        block.device_routine.set(routine);
        block.device_context.set(context);
        if device_queue::insert(&controller_at(controller).device_wait_queue, &block.wait_queue_entry, None) {
            return;
        }
        if run(target) == DEALLOCATE_OBJECT {
            free(controller);
        }
    }

    /// IoFreeController: KeRemoveDeviceQueue e a rotina do próximo; repete
    /// enquanto ela devolver DeallocateObject.
    pub fn free(controller: u64) {
        let queue = &controller_at(controller).device_wait_queue;
        loop {
            let entry = device_queue::remove(queue);
            if entry == 0 {
                return;
            }
            // A entrada é DeviceObject->Queue.Wcb.WaitQueueEntry.
            let offset = offset_of!(DeviceObject, queue) + offset_of!(DeviceObjectQueueView1, wcb) + offset_of!(WaitContextBlock, wait_queue_entry);
            if run(device_at(entry - offset as u64)) != DEALLOCATE_OBJECT {
                return;
            }
        }
    }

    /// Dispositivos esperando o controlador (diagnóstico e testes).
    pub fn queued(controller: u64) -> usize {
        device_queue::count(&controller_at(controller).device_wait_queue)
    }

    /// Controlador alocado (DeviceWaitQueue.Busy).
    pub fn busy(controller: u64) -> bool {
        controller_at(controller).device_wait_queue.busy.get() != 0
    }
}

pub mod start_io {
    use core::mem::offset_of;

    use super::device_queue;
    use crate::hal::amd64::native_call;
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::{DeviceObject, DevobjExtension, DriverObject, Irp, IrpTail, IrpTailOverlay, NtStruct};

    /// DEVOBJ_EXTENSION.StartIoFlags (bits do IoSetStartIoAttributes).
    const DOE_SIO_DEFERRED: u32 = 0x100;
    const DOE_SIO_NO_CANCEL: u32 = 0x200;

    fn device_at(device: u64) -> &'static DeviceObject {
        // SAFETY: DEVICE_OBJECT vivo do chamador.
        unsafe { DeviceObject::at(device) }
    }

    /// IRP que contém a Tail.Overlay.DeviceQueueEntry em `entry`.
    fn irp_of_entry(entry: u64) -> u64 {
        entry - (offset_of!(Irp, tail) + offset_of!(IrpTail, overlay) + offset_of!(IrpTailOverlay, device_queue_entry)) as u64
    }

    /// KeInitializeDeviceQueue na fila embutida do DEVICE_OBJECT.
    pub fn queue_initialize(device: u64) {
        device_queue::initialize(&device_at(device).device_queue);
    }

    /// DriverStartIo(DeviceObject, Irp) do driver dono.
    fn call_start_io(device: &DeviceObject, packet: u64) {
        // SAFETY: DeviceObject->DriverObject de um dispositivo vivo.
        let routine = unsafe { DriverObject::at(device.driver_object.get()) }.driver_start_io.get();
        if routine != 0 {
            native_call::call(routine, &[device.address(), packet, 0]);
        }
    }

    /// IoStartPacket(Device, Irp, PULONG Key, CancelFunction): livre vira
    /// CurrentIrp e roda o StartIo; ocupado entra na fila ordenada pela chave
    /// (sem chave, no fim).
    pub fn start_packet(device: u64, packet: u64, sort_key: u64, _cancel_routine: u64) {
        let target = device_at(device);
        device_queue::ensure_initialized(&target.device_queue);
        // SAFETY: PULONG Key do driver e o IRP vivo que ele entrega.
        let (key, irp) = unsafe { ((sort_key != 0).then(|| Field::<u32>::at(sort_key).get()), Irp::at(packet)) };
        if device_queue::insert(&target.device_queue, &irp.tail.overlay.device_queue_entry, Some(key.unwrap_or(u32::MAX))) {
            return;
        }
        target.current_irp.set(packet);
        call_start_io(target, packet);
    }

    /// IoStartNextPacket: tira o primeiro da fila (KeRemoveDeviceQueue) e
    /// dispara; fila vazia deixa o dispositivo livre.
    pub fn start_next_packet(device: u64, _cancelable: bool) {
        let target = device_at(device);
        device_queue::ensure_initialized(&target.device_queue);
        target.current_irp.set(0);
        let entry = device_queue::remove(&target.device_queue);
        if entry == 0 {
            return;
        }
        let next = irp_of_entry(entry);
        target.current_irp.set(next);
        call_start_io(target, next);
    }

    /// IoSetStartIoAttributes: DOE_SIO_DEFERRED / DOE_SIO_NO_CANCEL no
    /// DeviceObject->DeviceObjectExtension->StartIoFlags (só liga bits, como
    /// o NT).
    pub fn set_start_io_attributes(device: u64, deferred_start_io: bool, non_cancelable: bool) {
        let extension = device_at(device).device_object_extension.get();
        if extension == 0 {
            return;
        }
        // SAFETY: DeviceObjectExtension de um DEVICE_OBJECT vivo.
        let flags = &unsafe { DevobjExtension::at(extension) }.start_io_flags;
        if deferred_start_io {
            flags.atomic().fetch_or(DOE_SIO_DEFERRED, core::sync::atomic::Ordering::SeqCst);
        }
        if non_cancelable {
            flags.atomic().fetch_or(DOE_SIO_NO_CANCEL, core::sync::atomic::Ordering::SeqCst);
        }
    }
}
