//! Associação volume ↔ dispositivo de armazenamento — `system32/ntos/io/volume-parameters.js`.
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
use crate::ntos::inc::nt_abi::{devobj_extension, device_object, vpb};

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
    while guest::compare_exchange64(lock, 0, 1)? != 0 {
        cpu::pause();
    }
    let result = callback();
    let released = guest::compare_exchange64(lock, 1, 0)?;
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
    if guest::read64(filesystem + device_object::VPB) != 0 {
        return Ok(0xC000_000D);
    }
    with_lock(|| {
        let extension = guest::read64(filesystem + device_object::DEVICE_OBJECT_EXTENSION);
        let block = guest::read64(extension + devobj_extension::VPB);
        if block == 0 {
            return Ok(0xC000_000D);
        }
        if guest::read32(block + vpb::REFERENCE_COUNT) == 0 || guest::read16(block + vpb::FLAGS) as u32 & vpb::MOUNTED == 0 {
            return Ok(0xC000_026E);
        }
        let disk = guest::read64(block + vpb::REAL_DEVICE);
        guest::write64(output, disk);
        if device_objects::reference(disk)?.is_none() {
            return Err(KernelError::new("VPB refers to an unowned storage device"));
        }
        Ok(0)
    })
}
