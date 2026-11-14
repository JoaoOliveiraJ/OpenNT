//! Suporte de volume do FsRtl — estado de inicialização dos volumes,
//! desmontagem, contadores de disco por processador e o despacho de
//! "stack overflow" dos file systems.
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
//!   FsRtlNotifyVolumeEvent(Ex) 0x76d6e0 / 0x71b6f0: o evento de volume
//!     como notificação PnP de dispositivo alvo (seção própria abaixo).

use core::sync::atomic::{AtomicBool, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{FileObject, Guid, Kpcr, ObjectAttributes};
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
    if let Some(shared) = shared_user_data::data() {
        shared.dismount_count.atomic().fetch_add(1, Ordering::SeqCst);
    }
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

// ---- FsRtlNotifyVolumeEvent / FsRtlNotifyVolumeEventEx -------------------------------
//
// ntoskrnl 10.0.19041: FsRtlNotifyVolumeEventEx 0x71b6f0 (cauda fria em
// 0x84a976): IoGetRelatedTargetDevice(FileObject) acha o PDO do volume (a
// falha é devolvida); o EventCode escolhe o GUID gravado em
// Notification->Event e a entrega: DISMOUNT, DISMOUNT_FAILED, LOCK,
// LOCK_FAILED e UNLOCK pelo IoReportTargetDeviceChange (síncrono), os demais
// pelo IoReportTargetDeviceChangeAsynchronous sem callback; um código fora da
// tabela dá STATUS_INVALID_PARAMETER. O PDO é solto (ObDereferenceObject) e o
// resultado é o do IoGetRelatedTargetDevice, não o da entrega.
// FsRtlNotifyVolumeEvent 0x76d6e0 monta na pilha a
// TARGET_DEVICE_CUSTOM_NOTIFICATION vazia (Version 1, Size 0x24, FileObject
// NULL, NameBufferOffset -1) e chama o Ex.

/// TARGET_DEVICE_CUSTOM_NOTIFICATION (wdm.h): Version, Size, Event, FileObject,
/// NameBufferOffset e o primeiro byte de CustomDataBuffer.
#[repr(C)]
struct TargetDeviceCustomNotification {
    version: Field<u16>,
    size: Field<u16>,
    event: Guid,
    _pad_14: Reserved<0x4>,
    file_object: Field<u64>,
    name_buffer_offset: Field<i32>,
    custom_data_buffer: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for TargetDeviceCustomNotification {}

const _: () = {
    assert!(core::mem::size_of::<TargetDeviceCustomNotification>() == 0x28);
    assert!(core::mem::offset_of!(TargetDeviceCustomNotification, event) == 0x4);
    assert!(core::mem::offset_of!(TargetDeviceCustomNotification, file_object) == 0x18);
    assert!(core::mem::offset_of!(TargetDeviceCustomNotification, name_buffer_offset) == 0x20);
};

/// FIELD_OFFSET(TARGET_DEVICE_CUSTOM_NOTIFICATION, CustomDataBuffer).
const CUSTOM_NOTIFICATION_HEADER: u16 = 0x24;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// Os GUID_IO_VOLUME_* (ioevent.h), na ordem dos bytes da memória.
const VOLUME_DISMOUNT: [u8; 16] = [0xE8, 0x55, 0x6A, 0xD1, 0x59, 0x10, 0xD2, 0x11, 0x8F, 0xFD, 0x00, 0xA0, 0xC9, 0xA0, 0x6D, 0x32];
const VOLUME_DISMOUNT_FAILED: [u8; 16] = [0x78, 0xB1, 0xC5, 0xE3, 0x5D, 0x10, 0xD2, 0x11, 0x8F, 0xFD, 0x00, 0xA0, 0xC9, 0xA0, 0x6D, 0x32];
const VOLUME_LOCK: [u8; 16] = [0x74, 0x88, 0x70, 0x50, 0xAF, 0xC9, 0xD1, 0x11, 0x8F, 0xEF, 0x00, 0xA0, 0xC9, 0xA0, 0x6D, 0x32];
const VOLUME_LOCK_FAILED: [u8; 16] = [0x10, 0xED, 0x2E, 0xAE, 0xA8, 0x0B, 0xD2, 0x11, 0x8F, 0xFB, 0x00, 0xA0, 0xC9, 0xA0, 0x6D, 0x32];
const VOLUME_UNLOCK: [u8; 16] = [0x68, 0x3D, 0x8C, 0x9A, 0xCB, 0xD0, 0xD1, 0x11, 0x8F, 0xEF, 0x00, 0xA0, 0xC9, 0xA0, 0x6D, 0x32];
const VOLUME_MOUNT: [u8; 16] = [0x78, 0x48, 0x80, 0xB5, 0x96, 0x1A, 0xD2, 0x11, 0x8F, 0xFD, 0x00, 0xA0, 0xC9, 0xA0, 0x6D, 0x32];
const VOLUME_NEED_CHKDSK: [u8; 16] = [0x60, 0x09, 0x9A, 0x79, 0x0B, 0x0A, 0x03, 0x4E, 0xAD, 0x88, 0x2F, 0xA7, 0xC6, 0xCE, 0x74, 0x8A];
const VOLUME_WORM_NEAR_FULL: [u8; 16] = [0x82, 0xFF, 0xBF, 0xF3, 0xDE, 0xF3, 0xD2, 0x48, 0xAF, 0x95, 0x45, 0x7F, 0x80, 0xB7, 0x63, 0xF2];
const VOLUME_WEARING_OUT: [u8; 16] = [0xCA, 0x13, 0x31, 0x87, 0x86, 0x14, 0x08, 0x45, 0x82, 0xAC, 0xC3, 0xB2, 0xE5, 0x29, 0x7A, 0xAA];
const VOLUME_FORCE_CLOSED: [u8; 16] = [0x4F, 0xD8, 0x1A, 0x41, 0x3E, 0x43, 0xC2, 0x4D, 0xA5, 0xAE, 0x4A, 0x2D, 0x1A, 0x2D, 0xE6, 0x54];
const VOLUME_INFO_MAKE_COMPAT: [u8; 16] = [0xD2, 0xA0, 0xB9, 0x3A, 0x80, 0xEF, 0xCF, 0x45, 0x8C, 0xDC, 0xCB, 0xE0, 0x2A, 0x21, 0x29, 0x06];
const VOLUME_PREPARING_EJECT: [u8; 16] = [0x6E, 0xB1, 0x9E, 0xC7, 0xAC, 0x0D, 0x7A, 0x4E, 0xA8, 0x6C, 0xB2, 0x5C, 0xEE, 0xAA, 0x88, 0xF6];
const VOLUME_CHANGE_SIZE: [u8; 16] = [0xBE, 0x25, 0x16, 0x3A, 0x03, 0xAD, 0xF1, 0x49, 0x8E, 0xF8, 0x6B, 0xBA, 0xC1, 0x82, 0xD1, 0xFD];
const VOLUME_BACKGROUND_FORMAT: [u8; 16] = [0x86, 0xFC, 0xE5, 0xA2, 0xCD, 0xD5, 0x38, 0x40, 0xB2, 0xE3, 0x44, 0x45, 0x06, 0x5C, 0x23, 0x77];

/// (GUID, entrega síncrona) de cada FSRTL_VOLUME_* (1..=14).
fn volume_event(code: u32) -> Option<(&'static [u8; 16], bool)> {
    Some(match code {
        1 => (&VOLUME_DISMOUNT, true),
        2 => (&VOLUME_DISMOUNT_FAILED, true),
        3 => (&VOLUME_LOCK, true),
        4 => (&VOLUME_LOCK_FAILED, true),
        5 => (&VOLUME_UNLOCK, true),
        6 => (&VOLUME_MOUNT, false),
        7 => (&VOLUME_NEED_CHKDSK, false),
        8 => (&VOLUME_WORM_NEAR_FULL, false),
        9 => (&VOLUME_WEARING_OUT, false),
        10 => (&VOLUME_FORCE_CLOSED, false),
        11 => (&VOLUME_INFO_MAKE_COMPAT, false),
        12 => (&VOLUME_PREPARING_EJECT, false),
        13 => (&VOLUME_CHANGE_SIZE, false),
        14 => (&VOLUME_BACKGROUND_FORMAT, false),
        _ => return None,
    })
}

/// FsRtlNotifyVolumeEventEx(FileObject, EventCode, Event) -> NTSTATUS; `event`
/// é a TARGET_DEVICE_CUSTOM_NOTIFICATION do chamador.
pub fn notify_volume_event_ex(file_object: &FileObject, code: u32, event: u64) -> Result<u32, KernelError> {
    let (status, pdo) = crate::ntos::io::pnp::related_target_device(file_object.address())?;
    if (status as i32) < 0 {
        return Ok(status);
    }
    let result = match volume_event(code) {
        Some((guid, synchronous)) => {
            // SAFETY: a estrutura de notificação do file system (modo kernel).
            guest::write_bytes(unsafe { TargetDeviceCustomNotification::at(event) }.event.address(), guid);
            if synchronous {
                crate::ntos::io::pnp_notify::report_target_device_change(event);
            } else {
                crate::ntos::io::pnp_notify::report_target_device_change_asynchronous(event, 0, 0);
            }
            status
        }
        None => STATUS_INVALID_PARAMETER,
    };
    crate::ntos::ob::object_reference::dereference_with_tag(pdo, crate::ntos::ob::reference_trace::DEFAULT_TAG, true)?;
    Ok(result)
}

/// FsRtlNotifyVolumeEvent(FileObject, EventCode) -> NTSTATUS.
pub fn notify_volume_event(file_object: &FileObject, code: u32) -> Result<u32, KernelError> {
    let block = guest::alloc_bytes(TargetDeviceCustomNotification::SIZE);
    // SAFETY: bloco zerado recém-alocado do tamanho da estrutura.
    let notification = unsafe { TargetDeviceCustomNotification::at(block) };
    notification.version.set(1);
    notification.size.set(CUSTOM_NOTIFICATION_HEADER);
    notification.file_object.set(0);
    notification.name_buffer_offset.set(-1);
    notification.custom_data_buffer.set(0);
    let result = notify_volume_event_ex(file_object, code, block);
    guest::free_bytes(block);
    result
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
