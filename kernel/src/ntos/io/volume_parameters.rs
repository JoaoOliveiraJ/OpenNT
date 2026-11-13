//! Associação volume ↔ dispositivo de armazenamento.
//!
//! O IoVpbLock protege a associação do volume de sistema de arquivos com o
//! dispositivo de armazenamento, lida das estruturas nativas reais; nenhum
//! dispositivo é inferido de um caminho nem inventado para volume desmontado.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::cpu;
use crate::ntos::ke::{irql, pcr};
use crate::ntos::ob::objects::device as device_objects;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{DeviceObject, DevobjExtension, NtStruct, Vpb};

/// VPB_MOUNTED.
const VPB_MOUNTED: u16 = 0x0001;

/// KSPIN_LOCK do IoVpbLock (célula alocada em `init`).
fn lock_cell(lock: u64) -> &'static Field<u64> {
    // SAFETY: a célula de 8 bytes alocada em `init`, viva até o fim do sistema.
    unsafe { Field::<u64>::at(lock) }
}

static LOCK: AtomicU64 = AtomicU64::new(0);

pub fn init() -> Result<(), KernelError> {
    if LOCK.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let lock = guest::alloc_bytes(8);
    if lock == 0 {
        return Err(KernelError::new("I/O VPB lock allocation failed"));
    }
    LOCK.store(lock, Ordering::Release);
    pcr::set_io_vpb_lock(lock);
    Ok(())
}

pub fn with_lock<T>(callback: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    if irql::get_irql() > 2 {
        return Err(KernelError::new("VPB access above DISPATCH_LEVEL"));
    }
    init()?;
    let lock = LOCK.load(Ordering::Acquire);
    let old = irql::raise_irql(2);
    let cell = lock_cell(lock).atomic();
    while cell.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        cpu::pause();
    }
    let result = callback();
    let released = cell.compare_exchange(1, 0, Ordering::Release, Ordering::Relaxed).unwrap_or_else(|current| current);
    irql::lower_irql(old as u64);
    if released != 1 {
        return Err(KernelError::new("I/O VPB lock ownership corrupted"));
    }
    result
}

/// IoGetDiskDeviceObject: o dispositivo real do VPB montado, referenciado
/// sob o mesmo lock (a saída é gravada antes da referência, como no NT).
pub fn get_disk_device(filesystem: u64, output: u64) -> Result<u32, KernelError> {
    // Um dispositivo de armazenamento tem VPB próprio e não é volume de
    // sistema de arquivos; a recusa precede o lock e a leitura da saída.
    // SAFETY: DEVICE_OBJECT do sistema de arquivos, vivo do chamador.
    let device = unsafe { DeviceObject::at(filesystem) };
    if device.vpb.get() != 0 {
        return Ok(0xC000_000D);
    }
    with_lock(|| {
        let extension = device.device_object_extension.get();
        // SAFETY: DeviceObjectExtension de um DEVICE_OBJECT vivo.
        let block = if extension != 0 { unsafe { DevobjExtension::at(extension) }.vpb.get() } else { 0 };
        if block == 0 {
            return Ok(0xC000_000D);
        }
        // SAFETY: VPB montado, protegido pelo IoVpbLock retido.
        let volume = unsafe { Vpb::at(block) };
        if volume.reference_count.get() == 0 || volume.flags.get() & VPB_MOUNTED == 0 {
            return Ok(0xC000_026E);
        }
        let disk = volume.real_device.get();
        // SAFETY: PDEVICE_OBJECT* de saída do chamador de modo kernel.
        unsafe { Field::<u64>::at(output) }.set(disk);
        if device_objects::reference(disk)?.is_none() {
            return Err(KernelError::new("VPB refers to an unowned storage device"));
        }
        Ok(0)
    })
}
