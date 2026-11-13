//! Fixture dos autotestes do Cache Manager: um dispositivo de arquivo
//! sintético que atende as leituras e escritas de paginação do Cc a partir
//! de um arquivo em memória, como um file system atenderia (IRP_MJ_READ /
//! IRP_MJ_WRITE com IRP_PAGING_IO e MdlAddress), contando os IRPs e
//! recusando os que não têm a forma de IoPageRead/IoSynchronousPageWrite.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_cc::CcFileSizes;
use crate::ntos::inc::types::{DeviceObject, DriverObject, FileObject, IoStackLocation, Irp, Mdl, SectionObjectPointers};
use crate::ntos::io::io_manager::{self, irp_mj};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::file as file_objects;
use crate::rtl::SpinLock;

static BACKING: SpinLock<Vec<u8>> = SpinLock::new(Vec::new());
pub static READS: AtomicU32 = AtomicU32::new(0);
pub static WRITES: AtomicU32 = AtomicU32::new(0);
pub static BAD_IRPS: AtomicU32 = AtomicU32::new(0);
pub static LAST_READ_OFFSET: AtomicU64 = AtomicU64::new(0);
pub static LAST_READ_LENGTH: AtomicU64 = AtomicU64::new(0);
pub static LAST_WRITE_OFFSET: AtomicU64 = AtomicU64::new(0);
pub static LAST_WRITE_LENGTH: AtomicU64 = AtomicU64::new(0);
pub static FAIL_WRITES: AtomicBool = AtomicBool::new(false);

/// STATUS_IO_DEVICE_ERROR das escritas recusadas.
pub const WRITE_FAILURE: u32 = 0xC000_0185;
/// IRP_PAGING_IO | IRP_NOCACHE | IRP_SYNCHRONOUS_PAGING_IO.
const PAGING_FLAGS: u32 = 0x43;
/// MDL_PAGES_LOCKED | MDL_SOURCE_IS_NONPAGED_POOL.
const MDL_LOCKED_NONPAGED: i16 = 0x6;

/// Conteúdo de referência do arquivo sintético.
pub fn pattern(offset: u64) -> u8 {
    (offset.wrapping_mul(7) ^ (offset >> 9)) as u8
}

/// Byte atual do arquivo "no disco".
pub fn disk_byte(offset: u64) -> Option<u8> {
    BACKING.lock().get(offset as usize).copied()
}

extern "win64" fn dispatch(_device: u64, packet: u64) -> u64 {
    // SAFETY: o I/O Manager entrega um IRP vivo com a stack location corrente.
    let irp = unsafe { Irp::at(packet) };
    // SAFETY: CurrentStackLocation do mesmo IRP.
    let location = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
    let major = location.major_function.get();
    let length = location.parameters.read.length.get() as u64;
    let offset = location.parameters.read.byte_offset.quad_part.get() as u64;
    let descriptor = irp.mdl_address.get();
    let (mut status, mut information) = (0u32, 0u64);
    // SAFETY: MdlAddress de um IRP de paginação (verificado não nulo antes do uso).
    let mdl = (descriptor != 0).then(|| unsafe { Mdl::at(descriptor) });
    let well_formed = irp.flags.get() == PAGING_FLAGS && mdl.is_some_and(|mdl| mdl.byte_count.get() as u64 == length && mdl.mdl_flags.get() & MDL_LOCKED_NONPAGED == MDL_LOCKED_NONPAGED);
    match mdl.filter(|_| well_formed) {
        None => {
            BAD_IRPS.fetch_add(1, Ordering::SeqCst);
            status = 0xC000_000D;
        }
        Some(mdl) => {
            let buffer = mdl.mapped_system_va.get();
            if major == irp_mj::READ {
                READS.fetch_add(1, Ordering::SeqCst);
                LAST_READ_OFFSET.store(offset, Ordering::SeqCst);
                LAST_READ_LENGTH.store(length, Ordering::SeqCst);
                let bytes: Vec<u8> = {
                    let data = BACKING.lock();
                    let start = (offset as usize).min(data.len());
                    let available = (length as usize).min(data.len() - start);
                    let mut bytes = data[start..start + available].to_vec();
                    bytes.resize(length as usize, 0);
                    bytes
                };
                guest::write_bytes(buffer, &bytes);
                information = length;
            } else if major == irp_mj::WRITE {
                WRITES.fetch_add(1, Ordering::SeqCst);
                LAST_WRITE_OFFSET.store(offset, Ordering::SeqCst);
                LAST_WRITE_LENGTH.store(length, Ordering::SeqCst);
                if FAIL_WRITES.load(Ordering::SeqCst) {
                    status = WRITE_FAILURE;
                } else {
                    let bytes = guest::read_bytes(buffer, length as usize);
                    let mut data = BACKING.lock();
                    let start = (offset as usize).min(data.len());
                    let count = bytes.len().min(data.len() - start);
                    data[start..start + count].copy_from_slice(&bytes[..count]);
                    information = length;
                }
            }
        }
    }
    irp.io_status.status.set(status as i32);
    irp.io_status.information.set(information);
    io_manager::iof_complete_request(packet);
    status as u64
}

/// Driver, dispositivo, FILE_OBJECT com SECTION_OBJECT_POINTERS e um
/// CC_FILE_SIZES (AllocationSize = FileSize = ValidDataLength = `size`).
pub struct Fixture {
    pub driver: u64,
    pub device: u64,
    pub file: u64,
    pub pointers: u64,
    pub sizes: u64,
}

pub fn create(size: u64) -> Option<Fixture> {
    for counter in [&READS, &WRITES, &BAD_IRPS] {
        counter.store(0, Ordering::SeqCst);
    }
    FAIL_WRITES.store(false, Ordering::SeqCst);
    *BACKING.lock() = (0..size).map(pattern).collect();
    let (driver, device, pointers, sizes) = (guest::alloc_bytes(DriverObject::SIZE), guest::alloc_bytes(DeviceObject::SIZE), guest::alloc_bytes(SectionObjectPointers::SIZE), guest::alloc_bytes(CcFileSizes::SIZE));
    if driver == 0 || device == 0 || pointers == 0 || sizes == 0 {
        return None;
    }
    let routine = dispatch as extern "win64" fn(u64, u64) -> u64 as usize as u64;
    let routine = crate::ntos::mm::kernel_address::image_address(routine).unwrap_or(routine);
    // SAFETY: blocos zerados recém-alocados com o tamanho de cada tipo.
    let (driver_object, device_object, file_sizes) = unsafe { (DriverObject::at(driver), DeviceObject::at(device), CcFileSizes::at(sizes)) };
    driver_object.major_function[irp_mj::READ as usize].set(routine);
    driver_object.major_function[irp_mj::WRITE as usize].set(routine);
    device_object.driver_object.set(driver);
    device_object.stack_size.set(1);
    let file = file_objects::create(device, "\\opennt-cc-fixture").ok()?;
    // SAFETY: FILE_OBJECT recém-criado pelo Ob.
    unsafe { FileObject::at(file) }.section_object_pointer.set(pointers);
    file_sizes.allocation_size.quad_part.set(size as i64);
    file_sizes.file_size.quad_part.set(size as i64);
    file_sizes.valid_data_length.quad_part.set(size as i64);
    Some(Fixture { driver, device, file, pointers, sizes })
}

/// Segundo FILE_OBJECT do mesmo arquivo (mesmos SECTION_OBJECT_POINTERS).
pub fn open_another(fixture: &Fixture) -> u64 {
    let Ok(file) = file_objects::create(fixture.device, "\\opennt-cc-fixture") else { return 0 };
    // SAFETY: FILE_OBJECT recém-criado pelo Ob.
    unsafe { FileObject::at(file) }.section_object_pointer.set(fixture.pointers);
    file
}

pub fn close(file: u64) {
    let _ = file_objects::dereference(file);
}

pub fn destroy(fixture: Fixture) {
    close(fixture.file);
    for block in [fixture.driver, fixture.device, fixture.pointers, fixture.sizes] {
        guest::free_bytes(block);
    }
    BACKING.lock().clear();
}
