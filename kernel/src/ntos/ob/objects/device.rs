//! Corpos DEVICE_OBJECT.
//!
//! Extensões DEVOBJ_EXTENSION, referências do Object Manager e pilhas de
//! anexação sob o lock da base de dispositivos (publicado na PCR).
//! DEVICE_OBJECT.ReferenceCount continua reservado à contagem de I/O e
//! arquivos abertos.

use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;

use crate::ntos::ob::object_manager::ObjectData;
use crate::ntos::ob::objects::driver as driver_objects;
use crate::ntos::ob::object_types::{self, ObjectType};
use crate::ntos::ob::open_pointer::{self, ObjectOwner, Slot};
use crate::ntos::ob::object_access;
use crate::ntos::se::model::SecurityPolicy;
use crate::hal::cpu;
use crate::ntos::ke::{irql, pcr};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::types::{DeviceObject, DevobjExtension, DriverObject, Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;

/// IO_TYPE_DEVICE_OBJECT_EXTENSION.
const IO_TYPE_DEVICE_OBJECT_EXTENSION: i16 = 13;
/// DO_DEVICE_INITIALIZING.
const DO_DEVICE_INITIALIZING: u32 = 0x80;

/// O DEVICE_OBJECT de `pointer` (dispositivo vivo de um driver).
fn device(pointer: u64) -> &'static DeviceObject {
    // SAFETY: os chamadores passam DEVICE_OBJECTs vivos.
    unsafe { DeviceObject::at(pointer) }
}

/// A DEVOBJ_EXTENSION ligada por `register`.
fn device_extension(pointer: u64) -> &'static DevobjExtension {
    // SAFETY: extensões alocadas por `register`, vivas enquanto o dispositivo.
    unsafe { DevobjExtension::at(pointer) }
}

struct Record {
    extension: u64,
    references: u32,
    retired: bool,
    destroy: Option<fn(u64)>,
    unlink: Option<fn(u64)>,
    unlinked: bool,
    driver: u64,
    held: bool,
    /// Segurança capturada na criação, a do ObOpenObjectByPointer.
    security: SecurityPolicy,
}

/// O dono dos DEVICE_OBJECTs para o ObOpenObjectByPointer e o
/// ObReferenceObjectByHandle (`ob/open_pointer`).
struct DeviceOwner;

static OWNER: DeviceOwner = DeviceOwner;

impl ObjectOwner for DeviceOwner {
    fn object_type(&self, _pointer: u64) -> ObjectType {
        object_types::device_type()
    }
    fn reference(&self, pointer: u64) {
        let _ = reference(pointer);
    }
    fn dereference(&self, pointer: u64) {
        let _ = dereference(pointer);
    }
    fn security(&self, pointer: u64) -> SecurityPolicy {
        DEVICES.lock().get(&pointer).map(|record| record.security.clone()).unwrap_or_default()
    }
    fn data(&self, pointer: u64) -> ObjectData {
        ObjectData::pointer(pointer)
    }
}

static DEVICES: SpinLock<BTreeMap<u64, Record>> = SpinLock::new(BTreeMap::new());
static DATABASE_LOCK: SpinLock<u64> = SpinLock::new(0);

/// Uma palavra para o lock da base, publicada no bloco do processador.
fn database_lock() -> Result<u64, KernelError> {
    let mut lock = DATABASE_LOCK.lock();
    if *lock == 0 {
        let pointer = guest::alloc_bytes(Field::<u64>::SIZE);
        if pointer == 0 {
            return Err(KernelError::new("I/O database lock allocation failed"));
        }
        // SAFETY: alocação nova de um KSPIN_LOCK.
        unsafe { Field::<u64>::at(pointer) }.set(0);
        pcr::set_io_database_lock(pointer);
        *lock = pointer;
    }
    Ok(*lock)
}

/// Executa sob o lock da base em DISPATCH_LEVEL.
pub fn with_lock<T>(operation: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    if irql::get_irql() > 2 {
        return Err(KernelError::new("I/O database access above DISPATCH_LEVEL"));
    }
    // SAFETY: KSPIN_LOCK alocado por `database_lock`, nunca liberado.
    let lock = unsafe { Field::<u64>::at(database_lock()?) }.atomic();
    let previous = irql::raise_irql(2);
    while lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        cpu::pause();
    }
    let result = operation();
    lock.store(0, Ordering::Release);
    irql::lower_irql(previous as u64);
    result
}

/// Liga o dispositivo à extensão privada e retém o driver enquanto o corpo
/// existir; a extensão vai para DEVICE_OBJECT.DeviceObjectExtension.
pub fn register(pointer: u64, destroy: Option<fn(u64)>, unlink: Option<fn(u64)>) -> Result<u64, KernelError> {
    if DEVICES.lock().contains_key(&pointer) {
        return Err(KernelError::new("device already registered"));
    }
    database_lock()?;
    let extension = guest::alloc_bytes(DevobjExtension::SIZE);
    if extension == 0 {
        return Err(KernelError::new("device extension allocation failed"));
    }
    let object_extension = device_extension(extension);
    object_extension.type_.set(IO_TYPE_DEVICE_OBJECT_EXTENSION);
    object_extension.size.set(DevobjExtension::SIZE as u16);
    object_extension.device_object.set(pointer);
    device(pointer).device_object_extension.set(extension);
    let driver = device(pointer).driver_object.get();
    let held = driver != 0 && driver_objects::reference(driver).is_some();
    let security = object_access::capture(object_access::subject());
    DEVICES.lock().insert(pointer, Record { extension, references: 1, retired: false, destroy, unlink, unlinked: false, driver, held, security });
    object_types::device_type();
    open_pointer::register_owner(Slot::Device, is_device, &OWNER);
    object_types::bind_native(pointer, "Device")?;
    Ok(pointer)
}

pub fn is_device(pointer: u64) -> bool {
    DEVICES.lock().contains_key(&pointer)
}

/// Retém o corpo; dispositivos retirados sobrevivem com referências antigas.
pub fn reference(pointer: u64) -> Result<Option<u32>, KernelError> {
    let mut devices = DEVICES.lock();
    let Some(record) = devices.get_mut(&pointer) else { return Ok(None) };
    if record.references == 0 && !record.retired {
        return Err(KernelError::new("invalid device reference count"));
    }
    record.references += 1;
    Ok(Some(record.references))
}

/// Depois da retirada, espera arquivos e anexações pendentes; tira o
/// dispositivo da enumeração antes de liberar o corpo (IopDeleteDevice
/// 3604D4 -> 3605FC -> 3604E1).
fn collect(pointer: u64) {
    let (extension, unlink) = {
        let mut devices = DEVICES.lock();
        let Some(record) = devices.get_mut(&pointer) else { return };
        if !record.retired || device(pointer).reference_count.get() > 1 || device(pointer).attached_device.get() != 0 || device_extension(record.extension).attached_to.get() != 0 {
            return;
        }
        let unlink = if record.unlinked {
            None
        } else {
            record.unlinked = true;
            record.unlink
        };
        (record.extension, unlink)
    };
    if let Some(unlink) = unlink {
        unlink(pointer);
    }
    let removed = {
        let mut devices = DEVICES.lock();
        if devices.get(&pointer).is_some_and(|record| record.references != 0) {
            return;
        }
        devices.remove(&pointer)
    };
    let Some(record) = removed else { return };
    object_types::unbind_native(pointer);
    if let Some(destroy) = record.destroy {
        destroy(pointer);
    }
    guest::free_bytes(extension);
    if record.held {
        let _ = driver_objects::dereference(record.driver);
    }
}

pub fn dereference(pointer: u64) -> Result<Option<u32>, KernelError> {
    let count = {
        let mut devices = DEVICES.lock();
        let Some(record) = devices.get_mut(&pointer) else { return Ok(None) };
        if record.references == 0 {
            return Err(KernelError::new("device reference underflow"));
        }
        record.references -= 1;
        record.references
    };
    collect(pointer);
    Ok(Some(count))
}

/// IoDeleteDevice: marca a exclusão sob o lock e solta a referência inicial.
pub fn retire(pointer: u64) -> Result<bool, KernelError> {
    let Some(extension) = DEVICES.lock().get(&pointer).map(|record| if record.retired { 0 } else { record.extension }) else {
        return Ok(false);
    };
    if extension == 0 {
        return Ok(true);
    }
    with_lock(|| {
        let mut devices = DEVICES.lock();
        let record = devices.get_mut(&pointer).unwrap();
        record.retired = true;
        // DOE_DELETE_PENDING (sob o lock da base, e atômico para os demais bits).
        device_extension(extension).extension_flags.atomic().fetch_or(2, Ordering::SeqCst);
        record.references -= 1;
        Ok(())
    })?;
    collect(pointer);
    Ok(true)
}

/// Reavalia a exclusão depois de mudanças na pilha ou na contagem de uso.
pub fn changed(pointer: u64) {
    collect(pointer);
}

pub fn extension(pointer: u64) -> u64 {
    device(pointer).device_object_extension.get()
}

/// AttachedDevice até o topo da pilha.
pub fn top(pointer: u64) -> u64 {
    let mut pointer = pointer;
    loop {
        let next = device(pointer).attached_device.get();
        if next == 0 {
            return pointer;
        }
        pointer = next;
    }
}

/// AttachedTo das extensões até a base da pilha.
pub fn base(pointer: u64) -> u64 {
    let mut pointer = pointer;
    loop {
        let next = device_extension(extension(pointer)).attached_to.get();
        if next == 0 {
            return pointer;
        }
        pointer = next;
    }
}

/// IoGetAttachedDeviceReference / IoGetDeviceAttachmentBaseRef: busca e
/// retenção na mesma região protegida.
pub fn attached_reference(pointer: u64, lowest: bool) -> Result<u64, KernelError> {
    with_lock(|| {
        let found = if lowest { base(pointer) } else { top(pointer) };
        if reference(found)?.is_none() {
            return Err(KernelError::new("unregistered device reference"));
        }
        Ok(found)
    })
}

/// IoAttachDeviceToDeviceStack(Safe): acopla `source` ao topo de `target`.
/// Devolve o dispositivo inferior (0 quando o alvo está saindo ou cheio).
pub fn attach(source: u64, target: u64, output: u64) -> Result<u64, KernelError> {
    with_lock(|| {
        let lower = top(target);
        let (source_device, lower_device) = (device(source), device(lower));
        let source_extension = device_extension(extension(source));
        let lower_extension = device_extension(extension(lower));
        if source == lower || source_extension.attached_to.get() != 0 || source_device.attached_device.get() != 0 {
            return Err(KernelError::new("invalid device attachment"));
        }
        // SAFETY: PDEVICE_OBJECT* AttachedToDeviceObject de um chamador de kernel.
        let output = (output != 0).then(|| unsafe { Field::<u64>::at(output) });
        if lower_extension.extension_flags.get() & 0xF != 0 || lower_device.flags.get() & DO_DEVICE_INITIALIZING != 0 || lower_device.stack_size.get() as u8 >= 0x7D {
            if let Some(output) = output {
                output.set(0);
            }
            return Ok(0);
        }
        // O inferior vai para a saída antes de expor `source` ao despacho.
        if let Some(output) = output {
            output.set(lower);
        }
        source_device.stack_size.set((lower_device.stack_size.get() as u8).wrapping_add(1) as i8);
        source_device.alignment_requirement.set(lower_device.alignment_requirement.get());
        source_device.sector_size.set(lower_device.sector_size.get());
        // Bits copiados do inferior por OR atômico: drivers mexem nos mesmos
        // flags sem o lock da base.
        if lower_extension.extension_flags.get() & 0x10 != 0 {
            source_extension.extension_flags.atomic().fetch_or(0x10, Ordering::SeqCst);
        }
        if lower_device.flags.get() & 0x0800_0000 != 0 {
            source_device.flags.atomic().fetch_or(0x0800_0000, Ordering::SeqCst);
        }
        if lower_device.attached_device.atomic().compare_exchange(0, source, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(KernelError::new("device attachment changed outside I/O lock"));
        }
        lower_device.spare1.atomic().fetch_add(1, Ordering::SeqCst);
        source_extension.attached_to.set(lower);
        Ok(lower)
    })
}

/// IoDetachDevice: desconecta toda a cadeia acima do alvo (sem religar um
/// elemento intermediário) e reavalia a exclusão dos dois lados.
pub fn detach(target: u64) -> Result<u64, KernelError> {
    let upper = with_lock(|| {
        let upper = device(target).attached_device.get();
        if upper != 0 {
            device(target).attached_device.set(0);
            device_extension(extension(upper)).attached_to.set(0);
        }
        Ok(upper)
    })?;
    if upper != 0 {
        changed(upper);
        changed(target);
    }
    Ok(upper)
}

/// IoGetLowerDeviceObject: retém o inferior quando os flags permitem.
pub fn get_lower(pointer: u64) -> Result<u64, KernelError> {
    with_lock(|| {
        let object_extension = device_extension(extension(pointer));
        if object_extension.extension_flags.get() & 0xE != 0 {
            return Ok(0);
        }
        let lower = object_extension.attached_to.get();
        if lower != 0 && reference(lower)?.is_none() {
            return Err(KernelError::new("lower device is not an owned object"));
        }
        Ok(lower)
    })
}

/// IoEnumerateDeviceObjectList: conta a lista do driver, publica o total e
/// retém os dispositivos que cabem na saída.
pub fn enumerate(driver: u64, output: u64, buffer_length: u32, count_output: u64) -> Result<u32, KernelError> {
    let capacity = buffer_length >> 3;
    // SAFETY: DRIVER_OBJECT vivo do chamador.
    let driver = unsafe { DriverObject::at(driver) };
    with_lock(|| {
        let mut count = 0u32;
        let mut current = driver.device_object.get();
        while current != 0 {
            count += 1;
            current = device(current).next_device.get();
        }
        // SAFETY: PULONG ActualNumberDeviceObjects de um chamador de kernel.
        unsafe { Field::<u32>::at(count_output) }.set(count);
        // SAFETY: vetor PDEVICE_OBJECT[capacity] do mesmo chamador.
        let filled = capacity.min(count) as usize;
        let list: &[Field<u64>] = if filled != 0 { unsafe { Field::<u64>::array_at(output, filled) } } else { &[] };
        current = driver.device_object.get();
        let mut index = 0;
        while current != 0 && index < capacity {
            if reference(current)?.is_none() {
                return Err(KernelError::new("enumerated device is not an owned object"));
            }
            list[index as usize].set(current);
            current = device(current).next_device.get();
            index += 1;
        }
        Ok(if capacity < count { 0xC000_0023 } else { 0 })
    })
}

pub fn reference_count(pointer: u64) -> Option<u32> {
    DEVICES.lock().get(&pointer).map(|record| record.references)
}
