//! Corpos DEVICE_OBJECT.
//!
//! Extensões DEVOBJ_EXTENSION, referências do Object Manager e pilhas de
//! anexação sob o lock da base de dispositivos (publicado na PCR).
//! DEVICE_OBJECT.ReferenceCount continua reservado à contagem de I/O e
//! arquivos abertos.

use alloc::collections::BTreeMap;

use crate::ntos::ob::objects::driver as driver_objects;
use crate::ntos::ob::object_types;
use crate::hal::cpu;
use crate::ntos::ke::{irql, pcr};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const EXTENSION_OFFSET: u64 = 0x138;
const ATTACHED_DEVICE: u64 = 0x18;
const NEXT_DEVICE: u64 = 0x10;
const FLAGS: u64 = 0x30;
const STACK_SIZE: u64 = 0x4C;
const ALIGNMENT: u64 = 0x98;
const SECTOR_SIZE: u64 = 0x130;
const SPARE: u64 = 0x132;
const EXTENSION_FLAGS: u64 = 0x20;
const ATTACHED_TO: u64 = 0x30;

struct Record {
    extension: u64,
    references: u32,
    retired: bool,
    destroy: Option<fn(u64)>,
    unlink: Option<fn(u64)>,
    unlinked: bool,
    driver: u64,
    held: bool,
}

static DEVICES: SpinLock<BTreeMap<u64, Record>> = SpinLock::new(BTreeMap::new());
static DATABASE_LOCK: SpinLock<u64> = SpinLock::new(0);

/// Uma palavra para o lock da base, publicada no bloco do processador.
fn database_lock() -> Result<u64, KernelError> {
    let mut lock = DATABASE_LOCK.lock();
    if *lock == 0 {
        let pointer = guest::alloc_bytes(8);
        if pointer == 0 {
            return Err(KernelError::new("I/O database lock allocation failed"));
        }
        guest::write64(pointer, 0);
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
    let lock = database_lock()?;
    let previous = irql::raise_irql(2);
    while guest::compare_exchange64(lock, 0, 1)? != 0 {
        cpu::pause();
    }
    let result = operation();
    let _ = guest::compare_exchange64(lock, 1, 0);
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
    let extension = guest::alloc_bytes(0x70);
    if extension == 0 {
        return Err(KernelError::new("device extension allocation failed"));
    }
    guest::write16(extension, 13);
    guest::write16(extension + 2, 0x70);
    guest::write64(extension + 8, pointer);
    guest::write64(pointer + EXTENSION_OFFSET, extension);
    let driver = guest::read64(pointer + 8);
    let held = driver != 0 && driver_objects::reference(driver).is_some();
    DEVICES.lock().insert(pointer, Record { extension, references: 1, retired: false, destroy, unlink, unlinked: false, driver, held });
    object_types::device_type();
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
        if !record.retired || guest::read32(pointer + 4) > 1 || guest::read64(pointer + ATTACHED_DEVICE) != 0 || guest::read64(record.extension + ATTACHED_TO) != 0 {
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
        guest::write32(extension + EXTENSION_FLAGS, guest::read32(extension + EXTENSION_FLAGS) | 2);
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
    guest::read64(pointer + EXTENSION_OFFSET)
}

/// AttachedDevice até o topo da pilha.
pub fn top(pointer: u64) -> u64 {
    let mut pointer = pointer;
    loop {
        let next = guest::read64(pointer + ATTACHED_DEVICE);
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
        let next = guest::read64(extension(pointer) + ATTACHED_TO);
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
        let source_extension = extension(source);
        let lower_extension = extension(lower);
        if source == lower || guest::read64(source_extension + ATTACHED_TO) != 0 || guest::read64(source + ATTACHED_DEVICE) != 0 {
            return Err(KernelError::new("invalid device attachment"));
        }
        if guest::read32(lower_extension + EXTENSION_FLAGS) & 0xF != 0 || guest::read32(lower + FLAGS) & 0x80 != 0 || guest::read8(lower + STACK_SIZE) >= 0x7D {
            if output != 0 {
                guest::write64(output, 0);
            }
            return Ok(0);
        }
        // O inferior vai para a saída antes de expor `source` ao despacho.
        if output != 0 {
            guest::write64(output, lower);
        }
        guest::write8(source + STACK_SIZE, guest::read8(lower + STACK_SIZE) + 1);
        guest::write32(source + ALIGNMENT, guest::read32(lower + ALIGNMENT));
        guest::write16(source + SECTOR_SIZE, guest::read16(lower + SECTOR_SIZE));
        if guest::read32(lower_extension + EXTENSION_FLAGS) & 0x10 != 0 {
            guest::write32(source_extension + EXTENSION_FLAGS, guest::read32(source_extension + EXTENSION_FLAGS) | 0x10);
        }
        if guest::read32(lower + FLAGS) & 0x0800_0000 != 0 {
            guest::write32(source + FLAGS, guest::read32(source + FLAGS) | 0x0800_0000);
        }
        if guest::compare_exchange64(lower + ATTACHED_DEVICE, 0, source)? != 0 {
            return Err(KernelError::new("device attachment changed outside I/O lock"));
        }
        guest::write16(lower + SPARE, guest::read16(lower + SPARE) + 1);
        guest::write64(source_extension + ATTACHED_TO, lower);
        Ok(lower)
    })
}

/// IoDetachDevice: desconecta toda a cadeia acima do alvo (sem religar um
/// elemento intermediário) e reavalia a exclusão dos dois lados.
pub fn detach(target: u64) -> Result<u64, KernelError> {
    let upper = with_lock(|| {
        let upper = guest::read64(target + ATTACHED_DEVICE);
        if upper != 0 {
            guest::write64(target + ATTACHED_DEVICE, 0);
            guest::write64(extension(upper) + ATTACHED_TO, 0);
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
        let device_extension = guest::read64(pointer + EXTENSION_OFFSET);
        if guest::read32(device_extension + EXTENSION_FLAGS) & 0xE != 0 {
            return Ok(0);
        }
        let lower = guest::read64(device_extension + ATTACHED_TO);
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
    with_lock(|| {
        let mut count = 0u32;
        let mut device = guest::read64(driver + 8);
        while device != 0 {
            count += 1;
            device = guest::read64(device + NEXT_DEVICE);
        }
        guest::write32(count_output, count);
        device = guest::read64(driver + 8);
        let mut index = 0;
        while device != 0 && index < capacity {
            if reference(device)?.is_none() {
                return Err(KernelError::new("enumerated device is not an owned object"));
            }
            guest::write64(output + index as u64 * 8, device);
            device = guest::read64(device + NEXT_DEVICE);
            index += 1;
        }
        Ok(if capacity < count { 0xC000_0023 } else { 0 })
    })
}

pub fn reference_count(pointer: u64) -> Option<u32> {
    DEVICES.lock().get(&pointer).map(|record| record.references)
}
