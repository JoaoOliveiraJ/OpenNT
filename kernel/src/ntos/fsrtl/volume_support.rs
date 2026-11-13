//! Suporte de volume do FsRtl — estado de inicialização dos volumes,
//! desmontagem, contadores de disco por processador e o despacho de
//! "stack overflow" dos file systems (fsrtl\stackovf.c e afins).
//!
//! ntoskrnl 10.0.19045:
//!   FsRtlAreVolumeStartupApplicationsComplete 0x62e030: lê o byte
//!     FsRtlpVolumeStartupApplicationsComplete (0 na imagem; o NT o liga
//!     quando o smss termina os BootExecute). O OpenNT não roda essa fase,
//!     então o byte nunca é ligado e a resposta é FALSE.
//!   FsRtlDismountComplete 0x7739a0: DismountStatus >= 0 -> lock inc
//!     KUSER_SHARED_DATA.DismountCount (+0x2DC).
//!   FsRtlUpdateDiskCounters 0x30e7c0: lock xadd em KPRCB.FsCounters
//!     (FsBytesRead / FsBytesWritten), só os não nulos.
//!   FsRtlPostStackOverflow / FsRtlPostPagingFileStackOverflow 0x4f12c0 /
//!     0x4f12a0 -> FsRtlpPostStackOverflow 0x4f1354: o NT entrega
//!     StackOverflowRoutine(Context, Event) a uma thread de trabalho dedicada
//!     (com pilha nova) e o FS espera o Event. O OpenNT não tem essas threads
//!     reservadas: a rotina roda já, na thread corrente (o Event fica
//!     sinalizado pela própria rotina antes da espera do FS).

use core::sync::atomic::{AtomicBool, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{FileObject, Kpcr, KuserSharedData, ObjectAttributes};
use crate::ntos::ke::pcr;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::shared_user_data;
use crate::rtl::KernelError;

/// FsRtlpVolumeStartupApplicationsComplete.
static STARTUP_APPLICATIONS_COMPLETE: AtomicBool = AtomicBool::new(false);

pub fn startup_applications_complete() -> bool {
    STARTUP_APPLICATIONS_COMPLETE.load(Ordering::Acquire)
}

/// FsRtlDismountComplete(DeviceObject, DismountStatus).
pub fn dismount_complete(status: u32) {
    if (status as i32) < 0 {
        return;
    }
    // SAFETY: o frame da KUSER_SHARED_DATA, mapeado por identidade.
    let shared = unsafe { KuserSharedData::at(shared_user_data::frame()) };
    shared.dismount_count.atomic().fetch_add(1, Ordering::SeqCst);
}

/// FsRtlUpdateDiskCounters(BytesRead, BytesWritten): KPRCB.FsCounters do
/// processador corrente.
pub fn update_disk_counters(bytes_read: u64, bytes_written: u64) {
    // SAFETY: o KPCR do processador corrente (KPRCB embutido).
    let counters = &unsafe { Kpcr::at(pcr::get_pcr_address()) }.prcb.fs_counters;
    if bytes_read != 0 {
        counters.fs_bytes_read.atomic().fetch_add(bytes_read, Ordering::SeqCst);
    }
    if bytes_written != 0 {
        counters.fs_bytes_written.atomic().fetch_add(bytes_written, Ordering::SeqCst);
    }
}

/// FsRtlPostStackOverflow / FsRtlPostPagingFileStackOverflow(Context, Event,
/// StackOverflowRoutine).
pub fn post_stack_overflow(context: u64, event: u64, routine: u64) {
    native_call::call(routine, &[context, event]);
}

// ---- FsRtlCreateSectionForDataScan ---------------------------------------------------
//
// ntoskrnl 10.0.19045, RVA 0x35a570: SectionPageProtection só PAGE_READONLY /
// PAGE_READWRITE (senão STATUS_INVALID_PARAMETER_8); AllocationAttributes sem o
// bit 23 tem de ser SEC_COMMIT (senão STATUS_INVALID_PARAMETER_9); sem
// SectionObjectPointer -> STATUS_INVALID_FILE_FOR_SECTION; tamanho do arquivo 0
// -> STATUS_MAPPED_FILE_SIZE_ZERO; a seção tem o tamanho do arquivo
// (MaximumSize não é usado), entra com ObInsertObject (atributos do
// OBJECT_ATTRIBUTES) e sai referenciada em *SectionObject. O NT ainda adquire
// o arquivo pelo FsRtlAcquireToCreateMappedSection (callbacks do FS/filtros),
// repete após STATUS_FILE_LOCK_CONFLICT e zera o fim da última página pelo
// Cache Manager; o construtor de seção do OpenNT (`mm::section::create`)
// trata o arquivo sem essa aquisição.

const STATUS_INVALID_FILE_FOR_SECTION: u32 = 0xC000_0020;
const STATUS_MAPPED_FILE_SIZE_ZERO: u32 = 0xC000_0011;
const STATUS_INVALID_PARAMETER_8: u32 = 0xC000_00F6;
const STATUS_INVALID_PARAMETER_9: u32 = 0xC000_00F7;
const SEC_COMMIT: u32 = 0x800_0000;

/// Parâmetros de FsRtlCreateSectionForDataScan (as saídas são células do chamador).
pub struct DataScanSection<'a> {
    pub section_handle: &'a Field<u64>,
    pub section_object: &'a Field<u64>,
    pub section_file_size: Option<&'a Field<u64>>,
    pub file_object: &'a FileObject,
    pub desired_access: u32,
    pub object_attributes: Option<&'a ObjectAttributes>,
    pub protection: u32,
    pub allocation: u32,
}

pub fn create_section_for_data_scan(request: &DataScanSection) -> Result<u32, KernelError> {
    if request.protection & !6 != 0 || request.protection == 0 {
        return Ok(STATUS_INVALID_PARAMETER_8);
    }
    if request.allocation & !0x80_0000 != SEC_COMMIT {
        return Ok(STATUS_INVALID_PARAMETER_9);
    }
    if request.file_object.section_object_pointer.get() == 0 {
        return Ok(STATUS_INVALID_FILE_FOR_SECTION);
    }
    let scratch = guest::alloc_bytes(0x10);
    if scratch == 0 {
        return Ok(0xC000_009A);
    }
    // SAFETY: duas células de rascunho (LARGE_INTEGER do tamanho e PVOID da seção).
    let (size, section) = unsafe { (Field::<u64>::at(scratch), Field::<u64>::at(scratch + 8)) };
    let attributes_address = request.object_attributes.map_or(0, |attributes| attributes.address());
    let result = (|| -> Result<u32, KernelError> {
        let status = crate::ntos::init::exports::invoke_handler("FsRtlGetFileSize", &[request.file_object.address(), size.address()])? as u32;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        if size.get() == 0 {
            return Ok(STATUS_MAPPED_FILE_SIZE_ZERO);
        }
        let status = crate::ntos::mm::section::create::create_object(section.address(), request.desired_access, attributes_address, size.address(), request.protection, request.allocation, 0, request.file_object.address(), 0)?;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        let object = section.get();
        let attributes = request.object_attributes.map_or(0, |attributes| attributes.attributes.get());
        let handle = crate::ntos::ob::objects::section::open_handle(object, request.desired_access, attributes)?;
        request.section_handle.set(handle);
        request.section_object.set(object);
        if let Some(file_size) = request.section_file_size {
            file_size.set(size.get());
        }
        Ok(0)
    })();
    guest::free_bytes(scratch);
    result
}
