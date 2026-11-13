//! Fontes de erro de hardware do WHEA (NT: ntos\whea — whea.c, errsrc.c,
//! wheadrv.c) sem fontes de plataforma.
//!
//! O OpenNT não tem tabela HEST de ACPI nem PSHED: o WHEA começa inicializado
//! (WheapInitializationComplete) e com a WheapErrorSourceTable vazia. As
//! rotinas seguem o ntoskrnl 19041 sobre esse estado:
//!   WheaAddErrorSource rva 0x7af620: tipo de fonte HEST (WheapIsNonHestErrorSource
//!     0x3baa44 falso: tipos 0..3, 6, 7, 9, 10, 11) = STATUS_NOT_SUPPORTED; tipo
//!     acima de WheaErrSrcTypeDeviceDriver (0x10) = STATUS_INVALID_PARAMETER
//!     (WheapInitializeErrorSource 0x7afaa4); senão o descritor (0x3CC) é
//!     copiado, recebe o próximo ErrorSourceId (WheapAddErrorSource 0x3ba9c4) e
//!     fica WheaErrSrcStateStarted (2).
//!   WheaAddErrorSourceDeviceDriverV1 rva 0x3ba670 -> WheaAddErrorSourceDeviceDriver
//!     0x7af450: Version != 1 = STATUS_INVALID_PARAMETER_2; Initialize ou
//!     Uninitialize nulos = STATUS_INVALID_PARAMETER; descritor versão 0xB, tipo
//!     0x10, MaxSectionsPerRecord = MaxSectionsPerReport (1 no V1) + 2,
//!     MaxRawDataLength = MaxSectionsPerRecord * MaxSectionDataLength, Info =
//!     WHEA_DEVICE_DRIVER_DESCRIPTOR (SourceGuid, LogTag, Config.{Initialize,
//!     Uninitialize}, CreatorId DEFAULT_DEVICE_DRIVER_CREATOR_GUID, os limites);
//!     a Initialize do driver recebe (Context, ErrorSourceId).
//!   WheaGetErrorSource rva 0x5bb040: descritor de uma fonte iniciada, ou NULL.
//!   WheaRemoveErrorSource rva 0x95ceb0 (VOID): fonte não-HEST iniciada sai da
//!     tabela depois da Uninitialize.
//!   WheaConfigureErrorSource rva 0x9a00b0 / WheaUnconfigureErrorSource 0x9b38b0:
//!     tipo > 0x10 = STATUS_INVALID_PARAMETER; configurar um tipo já configurado
//!     = STATUS_UNSUCCESSFUL; com o WHEA inicializado a configuração nova devolve
//!     o WheapInitializeDeferredErrorSources (sem fontes adiadas = STATUS_SUCCESS);
//!     desconfigurar devolve STATUS_UNSUCCESSFUL em todos os tipos válidos.
//!   WheaInitializeRecordHeader rva 0x5bc940: cabeçalho CPER de 0x80 bytes.
//!   WheaReport*HwErrorDeviceDriverEx rva 0x5bc0f0/0x5bbfd0: fonte inexistente =
//!     WheaCreateHwErrorReportDeviceDriver NULL = STATUS_INSUFFICIENT_RESOURCES;
//!     a submissão termina no WheaReportHwError.
//!   WheaReportHwError rva 0x5bb070: severidade fatal leva a
//!     WHEA_UNCORRECTABLE_ERROR (0x124).
//!
//! Diferenças honestas: o OpenNT não persiste registros de erro nem gera os
//! eventos ETW do WHEA (um erro corrigido/recuperável é só aceito), e o
//! bugcheck fatal leva o pacote/descritor como parâmetro em vez do
//! WHEA_ERROR_RECORD montado pelo PSHED.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::inc::types::extra_storage::{WheaErrorPacketV2, WheaErrorRecordHeader, WheaErrorSourceConfigurationDeviceDriverV1, WheaErrorSourceDescriptor};
use crate::ntos::inc::types::{Guid, LargeInteger, NtStruct, TimeFields};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

const STATUS_SUCCESS: u32 = 0;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;

const SOURCE_STATE_CONFIGURED: u32 = 1;
const SOURCE_STATE_STARTED: u32 = 2;
const SOURCE_TYPE_DEVICE_DRIVER: u32 = 0x10;
const DESCRIPTOR_VERSION_11: u32 = 0xB;
/// Tipos de fonte que vêm da HEST (WheapIsNonHestErrorSource falso).
const HEST_TYPE_MASK: u32 = 0x0EC0;
/// Seções além das do driver em cada registro de uma fonte DeviceDriver.
const DEVICE_DRIVER_EXTRA_SECTIONS: u32 = 2;
/// WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1: um relatório por seção.
const V1_MAX_SECTIONS_PER_REPORT: u32 = 1;

/// GUIDs do ntoskrnl (bytes da imagem).
const WHEA_RECORD_CREATOR_GUID: [u8; 16] = [0xBD, 0xC4, 0x07, 0xCF, 0x89, 0xB7, 0x18, 0x4E, 0xB3, 0xC4, 0x1F, 0x73, 0x2C, 0xB5, 0x71, 0x31];
const DEFAULT_DEVICE_DRIVER_CREATOR_GUID: [u8; 16] = [0x8D, 0x7C, 0x21, 0x57, 0x66, 0x5E, 0xFB, 0x44, 0x80, 0x33, 0x9B, 0x74, 0xCA, 0xCE, 0xDF, 0x5B];

/// WHEA_ERROR_RECORD_HEADER: 'CPER', revisão 2.10, WheaErrSevNone, Timestamp válido.
const CPER_SIGNATURE: u32 = 0x5245_5043;
const CPER_REVISION: u16 = 0x0210;
const CPER_SIGNATURE_END: u32 = 0xFFFF_FFFF;
const SEVERITY_NONE: u32 = 3;
const VALID_BITS_TIMESTAMP: u32 = 2;

/// WHEA_ERROR_PACKET_V2.
const PACKET_SIGNATURE: u32 = 0x7450_7245; // 'ErPt'
const SEVERITY_FATAL: u32 = 1;
const WHEA_UNCORRECTABLE_ERROR: u32 = 0x124;

/// Fonte registrada: descritor (cópia), contexto e a Uninitialize do driver.
struct Source {
    descriptor: u64,
    context: u64,
    uninitialize: u64,
}

static SOURCES: SpinLock<Vec<Source>> = SpinLock::new(Vec::new());
static NEXT_ERROR_SOURCE_ID: AtomicU32 = AtomicU32::new(0);
static ERROR_RECORD_ID: AtomicU64 = AtomicU64::new(0);
/// Tipos configurados por WheaConfigureErrorSource (0..=0x10).
static CONFIGURED_TYPES: SpinLock<[bool; 0x11]> = SpinLock::new([false; 0x11]);

fn descriptor_at(address: u64) -> &'static WheaErrorSourceDescriptor {
    // SAFETY: descritores da tabela (cópias alocadas aqui) ou do chamador de modo kernel.
    unsafe { WheaErrorSourceDescriptor::at(address) }
}

fn set_guid(guid: &Guid, bytes: &[u8; 16]) {
    guest::write_bytes(guid.address(), bytes);
}

/// WheapIsNonHestErrorSource.
fn is_non_hest(source_type: u32) -> bool {
    if source_type <= 3 {
        return false;
    }
    !(source_type <= 0xB && (HEST_TYPE_MASK >> source_type) & 1 != 0)
}

/// Fonte iniciada com o ErrorSourceId dado (WheapGetErrorSource).
fn started(source: &Source, id: u32) -> bool {
    let descriptor = descriptor_at(source.descriptor);
    descriptor.error_source_id.get() == id && descriptor.state.get() == SOURCE_STATE_STARTED
}

/// WheaAddErrorSource(ErrorSource, Context): cópia do descritor na tabela.
/// Devolve o status e o ErrorSourceId atribuído.
fn add_source(descriptor: &WheaErrorSourceDescriptor, context: u64, uninitialize: u64) -> (u32, u32) {
    let source_type = descriptor.type_.get();
    if !is_non_hest(source_type) {
        return (STATUS_NOT_SUPPORTED, 0);
    }
    if source_type > SOURCE_TYPE_DEVICE_DRIVER {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let copy_address = guest::alloc_bytes(WheaErrorSourceDescriptor::SIZE);
    if copy_address == 0 {
        return (STATUS_INSUFFICIENT_RESOURCES, 0);
    }
    guest::write_bytes(copy_address, &guest::read_bytes(descriptor.address(), WheaErrorSourceDescriptor::SIZE as usize));
    let copy = descriptor_at(copy_address);
    let id = NEXT_ERROR_SOURCE_ID.fetch_add(1, Ordering::AcqRel);
    copy.error_source_id.set(id);
    copy.state.set(SOURCE_STATE_STARTED);
    SOURCES.lock().push(Source { descriptor: copy_address, context, uninitialize });
    (STATUS_SUCCESS, id)
}

/// WheaAddErrorSource(ErrorSource, Context).
pub fn add_error_source(descriptor: &WheaErrorSourceDescriptor, context: u64) -> u32 {
    add_source(descriptor, context, 0).0
}

/// WheaAddErrorSourceDeviceDriverV1(Context, Configuration, NumBuffersToPreallocate,
/// MaxDataLength).
pub fn add_device_driver_source_v1(context: u64, configuration: &WheaErrorSourceConfigurationDeviceDriverV1, buffers: u32, max_data_length: u32) -> u32 {
    if configuration.version.get() != 1 {
        return STATUS_INVALID_PARAMETER_2;
    }
    let initialize = configuration.initialize.get();
    let uninitialize = configuration.uninitialize.get();
    if initialize == 0 || uninitialize == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // Descritor DeviceDriver montado como o WheaAddErrorSourceDeviceDriver.
    let descriptor_address = guest::alloc_bytes(WheaErrorSourceDescriptor::SIZE);
    if descriptor_address == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let descriptor = descriptor_at(descriptor_address);
    let sections = V1_MAX_SECTIONS_PER_REPORT + DEVICE_DRIVER_EXTRA_SECTIONS;
    descriptor.length.set(WheaErrorSourceDescriptor::SIZE as u32);
    descriptor.version.set(DESCRIPTOR_VERSION_11);
    descriptor.type_.set(SOURCE_TYPE_DEVICE_DRIVER);
    descriptor.state.set(SOURCE_STATE_CONFIGURED);
    descriptor.max_raw_data_length.set(sections * max_data_length);
    descriptor.num_records_to_preallocate.set(buffers);
    descriptor.max_sections_per_record.set(sections);
    let info = &descriptor.device_driver;
    guest::write_bytes(info.source_guid.address(), &guest::read_bytes(configuration.source_guid.address(), 16));
    info.log_tag.set(configuration.log_tag.get());
    info.initialize.set(initialize);
    info.uninitialize.set(uninitialize);
    set_guid(&info.creator_id, &DEFAULT_DEVICE_DRIVER_CREATOR_GUID);
    info.max_section_data_length.set(max_data_length);
    info.max_sections_per_record.set(sections);
    let (status, id) = add_source(descriptor, context, uninitialize);
    guest::free_bytes(descriptor_address);
    if status == STATUS_SUCCESS {
        native_call::call(initialize, &[context, id as u64]);
    }
    status
}

/// WheaGetErrorSource(ErrorSourceId): descritor iniciado ou 0.
pub fn get_error_source(id: u32) -> u64 {
    SOURCES.lock().iter().find(|source| started(source, id)).map_or(0, |source| source.descriptor)
}

/// WheaRemoveErrorSource(ErrorSourceId).
pub fn remove_error_source(id: u32) {
    let removed = {
        let mut sources = SOURCES.lock();
        let Some(index) = sources.iter().position(|source| started(source, id)) else { return };
        if !is_non_hest(descriptor_at(sources[index].descriptor).type_.get()) {
            return;
        }
        sources.remove(index)
    };
    if removed.uninitialize != 0 {
        native_call::call(removed.uninitialize, &[removed.context]);
    }
    guest::free_bytes(removed.descriptor);
}

/// WheaConfigureErrorSource(SourceType, Configuration).
pub fn configure_error_source(source_type: u32, _configuration: u64) -> u32 {
    if source_type > SOURCE_TYPE_DEVICE_DRIVER {
        return STATUS_INVALID_PARAMETER;
    }
    let mut configured = CONFIGURED_TYPES.lock();
    if configured[source_type as usize] {
        return STATUS_UNSUCCESSFUL;
    }
    configured[source_type as usize] = true;
    // WheapInitializeDeferredErrorSources: nenhuma fonte adiada no OpenNT.
    STATUS_SUCCESS
}

/// WheaUnconfigureErrorSource(SourceType).
pub fn unconfigure_error_source(source_type: u32) -> u32 {
    if source_type > SOURCE_TYPE_DEVICE_DRIVER {
        return STATUS_INVALID_PARAMETER;
    }
    CONFIGURED_TYPES.lock()[source_type as usize] = false;
    STATUS_UNSUCCESSFUL
}

/// WheaInitializeRecordHeader(Header): CPER 2.10, severidade None, carimbo
/// de tempo do relógio de parede e o próximo RecordId.
pub fn initialize_record_header(header: &WheaErrorRecordHeader) -> u32 {
    guest::write_bytes(header.address(), &[0u8; WheaErrorRecordHeader::SIZE as usize]);
    header.signature.set(CPER_SIGNATURE);
    header.revision.set(CPER_REVISION);
    header.signature_end.set(CPER_SIGNATURE_END);
    header.severity.set(SEVERITY_NONE);
    header.valid_bits.set(VALID_BITS_TIMESTAMP);
    set_guid(&header.creator_id, &WHEA_RECORD_CREATOR_GUID);
    // WheapGetTimestamp: TIME_FIELDS do SystemTime em WHEA_TIMESTAMP.
    let time_address = guest::alloc_bytes(LargeInteger::SIZE);
    let fields_address = guest::alloc_bytes(TimeFields::SIZE);
    // SAFETY: blocos recém-alocados dos tamanhos dos tipos.
    let (time, fields) = unsafe { (LargeInteger::at(time_address), TimeFields::at(fields_address)) };
    time.quad_part.set(crate::ntos::ke::clock::system_time_100ns() as i64);
    crate::ntos::rtl::time::time_to_time_fields(time_address, fields_address);
    let year = fields.year.get() as i32;
    let stamp = &header.timestamp;
    stamp.seconds.set(fields.second.get() as u8);
    stamp.minutes.set(fields.minute.get() as u8);
    stamp.hours.set(fields.hour.get() as u8);
    stamp.day.set(fields.day.get() as u8);
    stamp.month.set(fields.month.get() as u8);
    stamp.year.set((year % 100) as u8);
    stamp.century.set((year / 100) as u8);
    guest::free_bytes(time_address);
    guest::free_bytes(fields_address);
    header.record_id.set(ERROR_RECORD_ID.fetch_add(1, Ordering::AcqRel) + 1);
    STATUS_SUCCESS
}

/// WheaReportHwError(ErrorPacket): fatal = WHEA_UNCORRECTABLE_ERROR; os
/// demais são aceitos (o OpenNT não tem log de erros do WHEA).
pub fn report_hw_error(packet: u64) -> u32 {
    if packet == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: WHEA_ERROR_PACKET de um driver de modo kernel.
    let error = unsafe { WheaErrorPacketV2::at(packet) };
    if error.signature.get() != PACKET_SIGNATURE {
        return STATUS_INVALID_PARAMETER;
    }
    if error.error_severity.get() == SEVERITY_FATAL {
        crate::ntos::ke::bugcheck::bug_check_ex(WHEA_UNCORRECTABLE_ERROR, error.error_source_type.get() as u64, packet, 0, 0);
    }
    STATUS_SUCCESS
}

/// WheaReportHwErrorDeviceDriverEx / WheaReportFatalHwErrorDeviceDriverEx
/// (ErrorSourceId, DeviceObject, ErrorData, ErrorDataLength, ..., SectionTypeGuid,
/// ..., ErrorSeverity, DeviceFriendlyName).
pub fn report_device_driver_error(source_id: u32, _device: u64, _data: u64, _length: u32, _section_type: u64, severity: u32, fatal: bool) -> u32 {
    let descriptor = get_error_source(source_id);
    if descriptor == 0 || descriptor_at(descriptor).type_.get() != SOURCE_TYPE_DEVICE_DRIVER {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if fatal || severity == SEVERITY_FATAL {
        crate::ntos::ke::bugcheck::bug_check_ex(WHEA_UNCORRECTABLE_ERROR, SOURCE_TYPE_DEVICE_DRIVER as u64, descriptor, source_id as u64, 0);
    }
    debug_print!("[whea] erro de dispositivo reportado: fonte {} severidade {}", source_id, severity);
    STATUS_SUCCESS
}
