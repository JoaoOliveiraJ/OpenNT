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
//! As duas usam a KDEVICE_QUEUE do Ke (`ke/device_queue.rs`), como o I/O
//! Manager do NT usa os KeInsert*/KeRemove*DeviceQueue.

pub mod controller {
    use core::mem::offset_of;

    use crate::ntos::ke::device_queue;
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
        if device_queue::insert(&controller_at(controller).device_wait_queue, &block.wait_queue_entry) {
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
        while let Some(entry) = device_queue::remove(queue) {
            // A entrada é DeviceObject->Queue.Wcb.WaitQueueEntry.
            let offset = offset_of!(DeviceObject, queue) + offset_of!(DeviceObjectQueueView1, wcb) + offset_of!(WaitContextBlock, wait_queue_entry);
            if run(device_at(entry.address() - offset as u64)) != DEALLOCATE_OBJECT {
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
    //! IoStartPacket, IoStartNextPacket(ByKey) e IoSetStartIoAttributes,
    //! como o I/O Manager do NT: o IRP entra na DeviceQueue do DEVICE_OBJECT
    //! pela Tail.Overlay.DeviceQueueEntry (KeInsertByKeyDeviceQueue com
    //! chave, KeInsertDeviceQueue sem) e, com a fila livre, vira CurrentIrp e
    //! vai ao DriverStartIo na hora. A rotina de cancelamento é instalada
    //! com o spin lock de cancelamento retido; um IRP que entrou na fila já
    //! cancelado vai direto a ela. Com DOE_SIO_DEFERRED (IoSetStartIoAttributes)
    //! um IoStartNextPacket chamado de dentro de um StartIo só registra o
    //! pedido no StartIoCount/StartIoFlags/StartIoKey da DEVOBJ_EXTENSION, e
    //! o laço de fora o executa, sem recursão.

    use core::mem::offset_of;
    use core::sync::atomic::Ordering;

    use crate::hal::amd64::native_call;
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::{DeviceObject, DevobjExtension, DriverObject, Irp, IrpTail, IrpTailOverlay, KdeviceQueueEntry, NtStruct};
    use crate::ntos::io::cancel;
    use crate::ntos::ke::{device_queue, irql};
    use crate::rtl::KernelError;

    /// DEVOBJ_EXTENSION.StartIoFlags.
    const DOE_SIO_NO_KEY: u32 = 0x20;
    const DOE_SIO_WITH_KEY: u32 = 0x40;
    const DOE_SIO_CANCELABLE: u32 = 0x80;
    const DOE_SIO_DEFERRED: u32 = 0x100;
    const DOE_SIO_NO_CANCEL: u32 = 0x200;
    /// Os três bits de um pedido adiado.
    const DOE_SIO_REQUEST: u32 = DOE_SIO_NO_KEY | DOE_SIO_WITH_KEY | DOE_SIO_CANCELABLE;

    fn device_at(device: u64) -> &'static DeviceObject {
        // SAFETY: DEVICE_OBJECT vivo do chamador.
        unsafe { DeviceObject::at(device) }
    }

    /// DeviceObject->DeviceObjectExtension (todo DEVICE_OBJECT do IoCreateDevice tem).
    fn extension_of(device: &DeviceObject) -> &'static DevobjExtension {
        // SAFETY: a DEVOBJ_EXTENSION de um DEVICE_OBJECT vivo.
        unsafe { DevobjExtension::at(device.device_object_extension.get()) }
    }

    /// IRP que contém a Tail.Overlay.DeviceQueueEntry `entry`.
    fn irp_of_entry(entry: &KdeviceQueueEntry) -> &'static Irp {
        let offset = (offset_of!(Irp, tail) + offset_of!(IrpTail, overlay) + offset_of!(IrpTailOverlay, device_queue_entry)) as u64;
        // SAFETY: as entradas da DeviceQueue são IRPs do IoStartPacket.
        unsafe { Irp::at(entry.address() - offset) }
    }

    /// KeInitializeDeviceQueue na fila embutida do DEVICE_OBJECT.
    pub fn queue_initialize(device: u64) {
        device_queue::initialize(&device_at(device).device_queue);
    }

    /// DriverStartIo(DeviceObject, Irp) do driver dono.
    fn call_start_io(device: &DeviceObject, irp: &Irp) {
        // SAFETY: DeviceObject->DriverObject de um dispositivo vivo.
        let routine = unsafe { DriverObject::at(device.driver_object.get()) }.driver_start_io.get();
        if routine != 0 {
            native_call::call(routine, &[device.address(), irp.address()]);
        }
    }

    /// O IRP vai ao StartIo: CurrentIrp, a rotina de cancelamento retirada
    /// com DOE_SIO_NO_CANCEL e o lock de cancelamento solto antes do
    /// DriverStartIo.
    fn dispatch(device: &DeviceObject, irp: &Irp, cancel_irql: Option<u8>) -> Result<(), KernelError> {
        device.current_irp.set(irp.address());
        if let Some(previous) = cancel_irql {
            if extension_of(device).start_io_flags.get() & DOE_SIO_NO_CANCEL != 0 {
                irp.cancel_routine.set(0);
            }
            cancel::release(previous)?;
        }
        call_start_io(device, irp);
        Ok(())
    }

    /// IoStartPacket(DeviceObject, Irp, PULONG Key, CancelFunction) em
    /// DISPATCH_LEVEL: fila livre vira CurrentIrp e roda o StartIo; ocupada
    /// guarda o IRP, ordenado pela chave quando há uma.
    pub fn start_packet(device: u64, packet: u64, key: u64, cancel_function: u64) -> Result<(), KernelError> {
        let target = device_at(device);
        // SAFETY: o IRP vivo que o driver entrega.
        let irp = unsafe { Irp::at(packet) };
        let previous = irql::raise_irql(irql::DISPATCH_LEVEL);
        let result = (|| {
            let cancel_irql = if cancel_function != 0 {
                let held = cancel::acquire()?;
                irp.cancel_routine.set(cancel_function);
                Some(held)
            } else {
                None
            };
            let entry = &irp.tail.overlay.device_queue_entry;
            let inserted = if key != 0 {
                // SAFETY: PULONG Key do driver.
                device_queue::insert_by_key(&target.device_queue, entry, unsafe { Field::<u32>::at(key) }.get())
            } else {
                device_queue::insert(&target.device_queue, entry)
            };
            match cancel_irql {
                _ if !inserted => dispatch(target, irp, cancel_irql),
                // Cancelado antes de entrar na fila: a rotina recebe o IRP
                // com o lock retido e o solta.
                Some(held) if irp.cancel.get() != 0 => {
                    irp.cancel_routine.set(0);
                    irp.cancel_irql.set(held);
                    native_call::call(cancel_function, &[device, packet]);
                    Ok(())
                }
                Some(held) => cancel::release(held),
                None => Ok(()),
            }
        })();
        irql::lower_irql(previous as u64);
        result
    }

    /// IopStartNextPacket / IopStartNextPacketByKey: CurrentIrp zerado, o
    /// próximo da fila (KeRemoveDeviceQueue, ou KeRemoveByKeyDeviceQueue com
    /// chave) vira CurrentIrp e vai ao StartIo; fila vazia fica livre.
    fn start_next(target: &DeviceObject, cancelable: bool, key: Option<u32>) -> Result<(), KernelError> {
        let cancel_irql = if cancelable { Some(cancel::acquire()?) } else { None };
        target.current_irp.set(0);
        let next = match key {
            Some(key) => device_queue::remove_by_key(&target.device_queue, key),
            None => device_queue::remove(&target.device_queue),
        };
        match next {
            Some(entry) => dispatch(target, irp_of_entry(entry), cancel_irql),
            None => cancel_irql.map_or(Ok(()), cancel::release),
        }
    }

    /// IopStartNextPacketByKeyEx (DOE_SIO_DEFERRED): só a chamada de fora
    /// (StartIoCount 1) executa; as aninhadas registram o pedido nos
    /// StartIoFlags/StartIoKey, e quem sai por último executa o que ficou.
    fn start_next_deferred(target: &DeviceObject, key: u32, flags: u32) -> Result<(), KernelError> {
        let extension = extension_of(target);
        let (mut key, mut flags) = (key, flags);
        loop {
            let count = extension.start_io_count.atomic().fetch_add(1, Ordering::SeqCst).wrapping_add(1);
            if count > 1 {
                extension.start_io_flags.set(extension.start_io_flags.get() | flags);
                extension.start_io_key.set(key as i32);
            } else {
                extension.start_io_flags.set(extension.start_io_flags.get() & !DOE_SIO_REQUEST);
                extension.start_io_key.set(0);
                let cancelable = flags & DOE_SIO_CANCELABLE != 0;
                if flags & DOE_SIO_WITH_KEY != 0 {
                    start_next(target, cancelable, Some(key))?;
                } else if flags & DOE_SIO_NO_KEY != 0 {
                    start_next(target, cancelable, None)?;
                }
            }
            if extension.start_io_count.atomic().fetch_sub(1, Ordering::SeqCst) != 1 {
                return Ok(());
            }
            flags = extension.start_io_flags.get() & DOE_SIO_REQUEST;
            key = extension.start_io_key.get() as u32;
            if flags & (DOE_SIO_NO_KEY | DOE_SIO_WITH_KEY) == 0 {
                return Ok(());
            }
        }
    }

    /// IoStartNextPacket(DeviceObject, Cancelable).
    pub fn start_next_packet(device: u64, cancelable: bool) -> Result<(), KernelError> {
        let target = device_at(device);
        if extension_of(target).start_io_flags.get() & DOE_SIO_DEFERRED != 0 {
            return start_next_deferred(target, 0, DOE_SIO_NO_KEY | if cancelable { DOE_SIO_CANCELABLE } else { 0 });
        }
        start_next(target, cancelable, None)
    }

    /// IoStartNextPacketByKey(DeviceObject, Cancelable, Key).
    pub fn start_next_packet_by_key(device: u64, cancelable: bool, key: u32) -> Result<(), KernelError> {
        let target = device_at(device);
        if extension_of(target).start_io_flags.get() & DOE_SIO_DEFERRED != 0 {
            return start_next_deferred(target, key, DOE_SIO_WITH_KEY | if cancelable { DOE_SIO_CANCELABLE } else { 0 });
        }
        start_next(target, cancelable, Some(key))
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
            flags.atomic().fetch_or(DOE_SIO_DEFERRED, Ordering::SeqCst);
        }
        if non_cancelable {
            flags.atomic().fetch_or(DOE_SIO_NO_CANCEL, Ordering::SeqCst);
        }
    }
}
