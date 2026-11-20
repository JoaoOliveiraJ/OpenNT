//! NtReadFileScatter e NtWriteFileGather de modo usuário (ntoskrnl 19041
//! 0x67e2a0 e 0x67ea40): a E/S sem buffer intermediário entre um arquivo e
//! uma lista de páginas inteiras (FILE_SEGMENT_ELEMENT).
//!
//! As checagens são as do 19041, na ordem de cada serviço:
//! - o handle (a leitura pede FILE_READ_DATA no ObReferenceObjectByHandle);
//!   o FILE_OBJECT tem de ser FO_NO_INTERMEDIATE_BUFFERING e não
//!   FO_SYNCHRONOUS_IO, o dispositivo relacionado não DO_BUFFERED_IO e de um
//!   tipo de file system (CD_ROM_FILE_SYSTEM, DFS, DISK_FILE_SYSTEM,
//!   FILE_SYSTEM, NETWORK_FILE_SYSTEM, TAPE_FILE_SYSTEM, DFS_VOLUME ou
//!   0x53), senão STATUS_INVALID_PARAMETER; a escrita pede depois
//!   FILE_WRITE_DATA ou, fora de um pipe, FILE_APPEND_DATA;
//! - o IO_STATUS_BLOCK sondado para escrita;
//! - na leitura: uma porta de conclusão com ApcRoutine (fora o bit 0) é
//!   STATUS_INVALID_PARAMETER; o ByteOffset (alinhado a 4) capturado; com o
//!   SectorSize do dispositivo, o Length múltiplo dele e o ByteOffset
//!   alinhado; a lista (alinhada a 8, uma entrada por página do Length)
//!   sondada, copiada e com cada página alinhada; a Key;
//! - na escrita: a lista primeiro, depois a porta com ApcRoutine, o
//!   ByteOffset e o alinhamento (o -1 do fim do arquivo e o -2 da posição
//!   corrente ficam fora), e a Key; um handle só com FILE_APPEND_DATA
//!   escreve no fim;
//! - o evento (EVENT_MODIFY_STATE) referenciado e limpo; sem ByteOffset
//!   (fora de pipes e mailslots) ou com ele negativo (fora o -1 da escrita),
//!   STATUS_INVALID_PARAMETER.
//!
//! Um arquivo de driver recebe o IRP com o MDL das páginas
//! (`irp_service::segment_transfer`). Um arquivo do volume servido pelo
//! file system embutido transfere os bytes ali mesmo
//! (`ps/user/file_io::segment_transfer`) e conclui como o
//! IopCompleteRequest de um pedido assíncrono atendido na hora: um erro só
//! volta como status; o sucesso grava o IO_STATUS_BLOCK, sinaliza o evento
//! (ou o do FILE_OBJECT, sem evento), enfileira a APC de usuário
//! (ApcRoutine(ApcContext, IoStatusBlock, 0)) e põe o pacote na porta de
//! conclusão do arquivo.

use alloc::vec::Vec;

use crate::ntos::inc::types::{DeviceObject, FileObject, IoStatusBlock, NtStruct};
use crate::ntos::io::completion::file_port;
use crate::ntos::io::file::{information, irp_service, query};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::user::{events, file_io, threads, user_apc};
use crate::ntos::ps::user_probe;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
/// FILE_OBJECT.Flags.
const FO_SYNCHRONOUS_IO: u32 = 0x2;
const FO_NO_INTERMEDIATE_BUFFERING: u32 = 0x8;
const FO_NAMED_PIPE: u32 = 0x80;
const FO_MAILSLOT: u32 = 0x200;
/// DEVICE_OBJECT.Flags.
const DO_BUFFERED_IO: u32 = 0x4;
/// Direitos de arquivo e de evento.
const FILE_READ_DATA: u32 = 0x1;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_APPEND_DATA: u32 = 0x4;
const EVENT_MODIFY_STATE: u32 = 0x2;
/// Os tipos de dispositivo até 0x36 aceitos (o bitmap do serviço):
/// CD_ROM_FILE_SYSTEM (3), DFS (6), DISK_FILE_SYSTEM (8), FILE_SYSTEM (9),
/// NETWORK_FILE_SYSTEM (0x14), TAPE_FILE_SYSTEM (0x20) e DFS_VOLUME (0x36).
const FILE_SYSTEM_DEVICE_TYPES: u64 = 0x0040_0001_0010_0348;
/// O outro tipo aceito, acima do bitmap.
const FILE_SYSTEM_DEVICE_TYPE_EXTRA: u32 = 0x53;
const PAGE_SIZE: u64 = 0x1000;

/// Os argumentos dos dois serviços.
#[derive(Clone, Copy)]
pub struct Request {
    pub handle: u64,
    pub event: u64,
    pub apc_routine: u64,
    pub apc_context: u64,
    pub io_status: u64,
    pub segments: u64,
    pub length: u32,
    pub byte_offset: u64,
    pub key: u64,
}

fn file_at(file: u64) -> &'static FileObject {
    // SAFETY: FILE_OBJECT referenciado durante o serviço.
    unsafe { FileObject::at(file) }
}

/// O dispositivo é de um file system que aceita a lista de páginas.
fn file_system_device(device: &DeviceObject) -> bool {
    let device_type = device.device_type.get();
    (device_type <= 0x36 && FILE_SYSTEM_DEVICE_TYPES & (1 << device_type) != 0) || device_type == FILE_SYSTEM_DEVICE_TYPE_EXTRA
}

/// O LARGE_INTEGER do ByteOffset (alinhado a 4, sondado e lido), ou None.
fn capture_offset(pointer: u64) -> Result<Option<i64>, u32> {
    if pointer == 0 {
        return Ok(None);
    }
    if pointer & 3 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if !user_probe::probe_user_read(pointer, 8) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    guest::try_read::<i64>(pointer).map(Some).map_err(|error| error.status)
}

/// A Key (ULONG opcional), sondada e lida.
fn capture_key(pointer: u64) -> Result<u32, u32> {
    if pointer == 0 {
        return Ok(0);
    }
    if !user_probe::probe_user_read(pointer, 4) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    guest::try_read::<u32>(pointer).map_err(|error| error.status)
}

/// A lista de páginas do Length (uma entrada de 8 bytes por página, a
/// última parcial): alinhada a 8 e sondada; com Length, copiada e cada
/// página alinhada (STATUS_INVALID_PARAMETER).
fn capture_segments(array: u64, length: u32) -> Result<Vec<u64>, u32> {
    let pages = (length as u64).div_ceil(PAGE_SIZE);
    let bytes = pages * 8;
    if bytes != 0 {
        if array & 7 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !user_probe::probe_user_read(array, bytes) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    let raw = guest::try_read_bytes(array, bytes as usize).map_err(|error| error.status)?;
    let segments: Vec<u64> = raw.chunks_exact(8).map(|entry| u64::from_le_bytes(entry.try_into().unwrap_or([0; 8]))).collect();
    if segments.iter().any(|&page| page & (PAGE_SIZE - 1) != 0) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(segments)
}

/// O alinhamento ao setor do dispositivo (um arquivo sem buffer
/// intermediário): o Length múltiplo do SectorSize e o ByteOffset
/// alinhado a ele; na escrita o -1 (fim do arquivo) e, num arquivo
/// síncrono, o -2 (posição corrente) não são conferidos.
fn sector_aligned(sector: u32, length: u32, offset: Option<i64>, write: bool, flags: u32) -> bool {
    if sector == 0 {
        return true;
    }
    if length & (sector - 1) != 0 && length % sector != 0 {
        return false;
    }
    let Some(offset) = offset else { return true };
    let exempt = write && (offset == -1 || (offset == -2 && flags & FO_SYNCHRONOUS_IO != 0));
    exempt || (offset as u32) & (sector - 1) == 0
}

/// Os argumentos capturados e conferidos.
struct Validated {
    segments: Vec<u64>,
    offset: Option<i64>,
    key: u32,
}

/// As checagens do serviço até o evento, na ordem dele.
fn validate(request: &Request, write: bool, file: u64, access: u32) -> Result<Validated, u32> {
    let object = file_at(file);
    let flags = object.flags.get();
    if !write && access & FILE_READ_DATA == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    let device = information::related_device_object(file).unwrap_or(0);
    if device == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: o dispositivo relacionado de um FILE_OBJECT referenciado.
    let device = unsafe { DeviceObject::at(device) };
    if flags & FO_NO_INTERMEDIATE_BUFFERING == 0 || flags & FO_SYNCHRONOUS_IO != 0 || device.flags.get() & DO_BUFFERED_IO != 0 || !file_system_device(device) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if write {
        let required = FILE_WRITE_DATA | if flags & FO_NAMED_PIPE == 0 { FILE_APPEND_DATA } else { 0 };
        if access & required == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
    }
    if !user_probe::probe_user_write(request.io_status, IoStatusBlock::SIZE) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let port_with_apc = object.completion_context.get() != 0 && request.apc_routine & !1 != 0;
    let sector = device.sector_size.get() as u32;
    let validated = if write {
        let segments = capture_segments(request.segments, request.length)?;
        if port_with_apc {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let offset = capture_offset(request.byte_offset)?;
        if !sector_aligned(sector, request.length, offset, true, flags) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Validated { segments, offset, key: capture_key(request.key)? }
    } else {
        if port_with_apc {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let offset = capture_offset(request.byte_offset)?;
        if !sector_aligned(sector, request.length, offset, false, flags) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let segments = capture_segments(request.segments, request.length)?;
        Validated { segments, offset, key: capture_key(request.key)? }
    };
    Ok(validated)
}

/// NtReadFileScatter (`write` = false) ou NtWriteFileGather de modo
/// usuário: o NTSTATUS do serviço.
pub fn transfer(request: &Request, write: bool) -> u32 {
    let selected = match query::resolve(request.handle, true) {
        Ok(selected) => selected,
        Err(status) => return status,
    };
    let file = selected.pointer;
    if !file_objects::reference(file).is_ok_and(|referenced| referenced.is_some()) {
        return STATUS_INVALID_HANDLE;
    }
    let status = transfer_referenced(request, write, file, selected.access);
    let _ = file_objects::dereference(file);
    status
}

fn transfer_referenced(request: &Request, write: bool, file: u64, access: u32) -> u32 {
    let validated = match validate(request, write, file, access) {
        Ok(validated) => validated,
        Err(status) => return status,
    };
    let flags = file_at(file).flags.get();
    // Só FILE_APPEND_DATA: a escrita vai para o fim do arquivo.
    let mut offset = validated.offset;
    if write && access & (FILE_WRITE_DATA | FILE_APPEND_DATA) == FILE_APPEND_DATA {
        offset = offset.map(|_| -1);
    }
    let event = if request.event != 0 {
        match events::reference(request.event, EVENT_MODIFY_STATE) {
            Ok(event) => {
                dispatcher::clear_event(event.pointer);
                Some(event)
            }
            Err(status) => return status,
        }
    } else {
        None
    };
    let release = |event: Option<alloc::sync::Arc<events::EventObject>>, status: u32| {
        if let Some(event) = event {
            events::release(&event);
        }
        status
    };
    let byte_offset = match offset {
        None if flags & (FO_NAMED_PIPE | FO_MAILSLOT) == 0 => return release(event, STATUS_INVALID_PARAMETER),
        None => 0,
        Some(value) if value < 0 && !(write && value == -1) => return release(event, STATUS_INVALID_PARAMETER),
        Some(value) => value,
    };
    if information::related_device(file).unwrap_or(0) != 0 {
        // O IRP referencia o evento de novo; esta referência sai aqui.
        let arguments = irp_service::SegmentTransfer { handle: request.handle, event: request.event, apc_routine: request.apc_routine, apc_context: request.apc_context, io_status: request.io_status, length: request.length, byte_offset, key: validated.key };
        let status = irp_service::segment_transfer(&arguments, &validated.segments, write);
        return release(event, status);
    }
    dispatcher::clear_event(file_at(file).event.address());
    let (status, information) = match file_io::segment_transfer(request.handle, &validated.segments, request.length, byte_offset, validated.key, write) {
        Ok(result) => result,
        Err(status) => return release(event, status),
    };
    let _ = guest::try_write::<i32>(request.io_status + core::mem::offset_of!(IoStatusBlock, status) as u64, status as i32);
    let _ = guest::try_write::<u64>(request.io_status + core::mem::offset_of!(IoStatusBlock, information) as u64, information);
    match &event {
        Some(event) => {
            dispatcher::set_event(event.pointer);
        }
        None => {
            if !file_port::skips_file_event(file) {
                dispatcher::set_event(file_at(file).event.address());
            }
        }
    }
    if request.apc_routine != 0 {
        if let Some(thread) = threads::current() {
            let _ = user_apc::queue(&thread, request.apc_routine, request.apc_context, request.io_status, 0, false, false);
        }
    } else {
        file_port::complete(file, request.apc_context, status, information, false);
    }
    release(event, status)
}
