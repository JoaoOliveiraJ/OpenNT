//! NtCopyFileChunk: o caminho de dados do CopyFile do kernelbase
//! (BaseCopyStream), como o do ntoskrnl 19041 (0x5cdd80).
//!
//! - Flags diferente de zero é STATUS_INVALID_PARAMETER. SourceOffset é
//!   obrigatório (alinhado a 4, capturado); o IO_STATUS_BLOCK é sondado para
//!   escrita. O buffer do pedido sai do pool (Length + 0x48 bytes, 'IoCp');
//!   sem ele, STATUS_INSUFFICIENT_RESOURCES.
//! - Origem com FILE_READ_DATA; destino com FILE_WRITE_DATA ou, fora de pipes
//!   nomeados, FILE_APPEND_DATA (só FILE_APPEND_DATA escreve no fim).
//! - Os parâmetros da escrita são validados antes da leitura, como os de um
//!   NtWriteFile não síncrono (IopValidateAndGetWriteParameters): DestOffset
//!   obrigatório (salvo pipes e mailslots) e não negativo (salvo
//!   FILE_WRITE_TO_END_OF_FILE); sem buffer intermediário, Length e o offset
//!   alinhados ao setor.
//! - A origem decide o modo. Síncrona (FO_SYNCHRONOUS_IO):
//!   FILE_USE_FILE_POINTER_POSITION lê da posição corrente; o retorno é o
//!   status da escrita no IO_STATUS_BLOCK e o evento é sinalizado.
//!   Assíncrona: leitura aceita vira STATUS_PENDING, com o IO_STATUS_BLOCK e
//!   o evento da escrita já concluídos.
//! - Uma leitura que falha sem ficar pendente (STATUS_END_OF_FILE com o
//!   offset no fim ou depois dele) volta direto, sem tocar no
//!   IO_STATUS_BLOCK nem no evento; o BaseCopyStream trata esse retorno.
//! - Destino sem buffer intermediário: a escrita é arredondada ao setor
//!   (limitada a Length), com o resto zerado (IopCopyCompleteReadIrp); o
//!   kernelbase trunca depois.
//! - Cada lado é um arquivo do volume do kernel (a descrição aberta) ou um
//!   arquivo de driver (IRP_MJ_READ/IRP_MJ_WRITE de modo kernel sobre o
//!   buffer do pool, `irp_service::DriverFile`).

use alloc::sync::Arc;

use crate::ntos::ex::pool_allocation;
use crate::ntos::io::file::irp_service::DriverFile;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::events::{self, EventObject};
use crate::ntos::ps::user::file_io;
use crate::ntos::ps::user::file_objects::UserFile;
use crate::ntos::ps::user::state::{self, UserHandle};
use crate::rtl::KernelError;

const STATUS_PENDING: u32 = 0x103;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
const STATUS_IO_DEVICE_ERROR: u32 = 0xC000_0185;
const FILE_READ_DATA: u32 = 0x1;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_APPEND_DATA: u32 = 0x4;
const EVENT_MODIFY_STATE: u32 = 0x2;
const FO_SYNCHRONOUS_IO: u32 = 0x2;
const FO_NO_INTERMEDIATE_BUFFERING: u32 = 0x8;
const FO_NAMED_PIPE: u32 = 0x80;
const FO_MAILSLOT: u32 = 0x200;
/// ExAllocatePool2: POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED |
/// POOL_FLAG_USE_QUOTA, Length + 0x48 bytes, tag 'IoCp'; os dados ficam
/// depois do cabeçalho.
const POOL_FLAGS: u64 = 0x43;
const POOL_TAG: u32 = u32::from_le_bytes(*b"IoCp");
const HEADER: u64 = 0x48;
/// Setor dos arquivos do volume do kernel (o mesmo do NtReadFile deles).
const VOLUME_SECTOR: u32 = 512;
const FILE_WRITE_TO_END_OF_FILE: i64 = -1;
const FILE_USE_FILE_POINTER_POSITION: i64 = -2;

/// Os argumentos de NtCopyFileChunk.
pub struct Arguments {
    pub source: u64,
    pub destination: u64,
    pub event: u64,
    pub io_status: u64,
    pub length: u32,
    pub source_offset: u64,
    pub destination_offset: u64,
    pub source_key: u64,
    pub destination_key: u64,
    pub flags: u32,
}

/// Um lado da cópia.
enum Side {
    Volume { entry: Arc<UserHandle>, file: Arc<UserFile> },
    Driver(DriverFile),
}

impl Side {
    fn open(handle: u64) -> Result<Side, u32> {
        match state::get_user_handle(handle) {
            Some(entry) if entry.kind() == "file" => file_io::volume_open(handle).map(|(entry, file)| Side::Volume { entry, file }),
            Some(entry) if entry.kind() != "device" => Err(STATUS_OBJECT_TYPE_MISMATCH),
            // Arquivo de driver, ou handle nativo (resolvido pelo FILE_OBJECT).
            _ => DriverFile::reference(handle).map(Side::Driver),
        }
    }

    fn access(&self) -> u32 {
        match self {
            Side::Volume { entry, .. } => entry.access(),
            Side::Driver(file) => file.access(),
        }
    }

    /// FILE_OBJECT.Flags; no volume do kernel, os bits que vêm das opções da
    /// abertura.
    fn flags(&self) -> u32 {
        match self {
            Side::Volume { file, .. } => (if file.options & 0x30 != 0 { FO_SYNCHRONOUS_IO } else { 0 }) | if file.options & 8 != 0 { FO_NO_INTERMEDIATE_BUFFERING } else { 0 },
            Side::Driver(file) => file.flags(),
        }
    }

    fn sector_size(&self) -> u32 {
        match self {
            Side::Volume { .. } => VOLUME_SECTOR,
            Side::Driver(file) => file.sector_size(),
        }
    }

    /// AlignmentRequirement do dispositivo (o volume do kernel não tem).
    fn alignment(&self) -> u64 {
        match self {
            Side::Volume { .. } => 0,
            Side::Driver(file) => file.alignment_requirement() as u64,
        }
    }

    fn position(&self) -> i64 {
        match self {
            Side::Volume { file, .. } => file.position() as i64,
            Side::Driver(file) => file.position(),
        }
    }
}

fn status_of(error: KernelError) -> u32 {
    if error.status != 0 { error.status } else { STATUS_IO_DEVICE_ERROR }
}

/// ULONG de modo usuário opcional (as chaves), só sondado e lido.
fn probe_key(pointer: u64) -> Result<(), u32> {
    if pointer != 0 && (!state::probe_user_read(pointer, 4) || guest::try_read::<u32>(pointer).is_err()) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(())
}

/// O evento opcional, referenciado com EVENT_MODIFY_STATE e zerado.
fn reference_event(handle: u64) -> Result<Option<Arc<EventObject>>, u32> {
    if handle == 0 {
        return Ok(None);
    }
    let event = events::reference(handle, EVENT_MODIFY_STATE)?;
    dispatcher::clear_event(event.pointer);
    Ok(Some(event))
}

/// Sem buffer intermediário: Length múltiplo do setor, o buffer no
/// alinhamento do dispositivo e o offset (quando conta) alinhado ao setor.
fn check_unbuffered(side: &Side, length: u32, buffer: u64, offset: Option<i64>) -> Result<(), u32> {
    if side.flags() & FO_NO_INTERMEDIATE_BUFFERING == 0 {
        return Ok(());
    }
    let sector = side.sector_size();
    let misaligned = (sector != 0 && length % sector != 0) || buffer & side.alignment() != 0 || offset.is_some_and(|offset| sector != 0 && (offset as u32) & (sector - 1) != 0);
    if misaligned { Err(STATUS_INVALID_PARAMETER) } else { Ok(()) }
}

/// NtCopyFileChunk de modo usuário.
pub fn copy_file_chunk(arguments: &Arguments) -> u32 {
    if arguments.flags != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if arguments.source_offset & 3 != 0 {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    let source_offset = match state::capture_large_integer(arguments.source_offset) {
        Ok(offset) => offset,
        Err(status) => return status,
    };
    if arguments.io_status == 0 || !state::probe_user_write(arguments.io_status, 16) {
        return STATUS_ACCESS_VIOLATION;
    }
    let block = match pool_allocation::allocate_pool2(POOL_FLAGS, arguments.length as u64 + HEADER, POOL_TAG) {
        Ok(block) if block != 0 => block,
        _ => return STATUS_INSUFFICIENT_RESOURCES,
    };
    let mut event = None;
    let status = copy(arguments, source_offset, block + HEADER, &mut event).unwrap_or_else(|status| status);
    if let Some(event) = &event {
        events::release(event);
    }
    let _ = pool_allocation::free(block, POOL_TAG as u64);
    status
}

fn copy(arguments: &Arguments, source_offset: i64, buffer: u64, event: &mut Option<Arc<EventObject>>) -> Result<u32, u32> {
    let source = Side::open(arguments.source)?;
    if source.access() & FILE_READ_DATA == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    let destination = Side::open(arguments.destination)?;
    let destination_flags = destination.flags();
    let write_access = FILE_WRITE_DATA | if destination_flags & FO_NAMED_PIPE != 0 { 0 } else { FILE_APPEND_DATA };
    if destination.access() & write_access == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    let synchronous = source.flags() & FO_SYNCHRONOUS_IO != 0;
    // Os parâmetros da escrita, como os de um NtWriteFile não síncrono.
    let mut write_offset = None;
    if arguments.destination_offset != 0 {
        if arguments.destination_offset & 3 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        write_offset = Some(state::capture_large_integer(arguments.destination_offset)?);
    }
    probe_key(arguments.destination_key)?;
    check_unbuffered(&destination, arguments.length, buffer, write_offset.filter(|&offset| offset != FILE_WRITE_TO_END_OF_FILE))?;
    if destination.access() & (FILE_WRITE_DATA | FILE_APPEND_DATA) == FILE_APPEND_DATA {
        write_offset = Some(FILE_WRITE_TO_END_OF_FILE);
    }
    if !synchronous {
        *event = reference_event(arguments.event)?;
    }
    let write_offset = match write_offset {
        Some(offset) if offset >= 0 || offset == FILE_WRITE_TO_END_OF_FILE => offset,
        None if destination_flags & (FO_NAMED_PIPE | FO_MAILSLOT) != 0 => 0,
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    if synchronous {
        *event = reference_event(arguments.event)?;
    }
    // A leitura (o IopReadFile).
    probe_key(arguments.source_key)?;
    check_unbuffered(&source, arguments.length, buffer, Some(source_offset))?;
    let read_offset = if synchronous && source_offset == FILE_USE_FILE_POINTER_POSITION { source.position() } else { source_offset };
    if read_offset < 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let read = match read(&source, buffer, arguments.length, read_offset) {
        Ok(read) => read,
        // Falha depois de STATUS_PENDING (só num arquivo de driver): vai ao
        // IO_STATUS_BLOCK e ao evento, como a escrita concluída com ela.
        Err((status, true)) => return Ok(finish(arguments, event, synchronous, status, 0)),
        Err((status, false)) => return Err(status),
    };
    if let (Side::Volume { file, .. }, true) = (&source, synchronous) {
        file.set_position(read_offset as u64 + read);
    }
    // Destino sem buffer intermediário: o tamanho da escrita sobe ao setor,
    // limitado a Length, com o resto zerado.
    let mut count = read;
    if destination_flags & FO_NO_INTERMEDIATE_BUFFERING != 0 {
        let sector = match destination.sector_size() {
            0 => 0x1000,
            sector => sector,
        } as u64;
        count = (read.div_ceil(sector) * sector).min(arguments.length as u64);
        if count > read {
            guest::write_bytes(buffer + read, &alloc::vec![0; (count - read) as usize]);
        }
    }
    let (status, written) = write(&destination, buffer, count, write_offset);
    Ok(finish(arguments, event, synchronous, status, written))
}

/// A conclusão: IO_STATUS_BLOCK e evento; síncrona devolve o status,
/// assíncrona STATUS_PENDING.
fn finish(arguments: &Arguments, event: &Option<Arc<EventObject>>, synchronous: bool, status: u32, information: u64) -> u32 {
    let written = state::set_user_iosb(arguments.io_status, status, information).is_ok();
    if let Some(event) = event {
        dispatcher::set_event(event.pointer);
    }
    match (synchronous, written) {
        (false, _) => STATUS_PENDING,
        (true, true) => status,
        (true, false) => STATUS_ACCESS_VIOLATION,
    }
}

/// Lê até `length` bytes em `buffer`. O erro leva o status e se o pedido
/// ficou pendente antes de falhar.
fn read(side: &Side, buffer: u64, length: u32, offset: i64) -> Result<u64, (u32, bool)> {
    match side {
        Side::Volume { file, .. } => {
            let file = &file.file;
            if file.directory() {
                return Err((STATUS_FILE_IS_A_DIRECTORY, false));
            }
            if length == 0 {
                return Ok(0);
            }
            let offset = offset as u64;
            if offset >= file.size() {
                return Err((STATUS_END_OF_FILE, false));
            }
            let data = file.read_at(offset, (length as u64).min(file.size() - offset)).map_err(|error| (status_of(error), false))?;
            guest::write_bytes(buffer, &data);
            Ok(data.len() as u64)
        }
        Side::Driver(file) => {
            let result = file.transfer(false, buffer, length, offset, 0);
            if (result.status as i32) < 0 { Err((result.status, result.pending)) } else { Ok(result.information.min(length as u64)) }
        }
    }
}

/// Escreve `count` bytes de `buffer`: (status, bytes escritos).
fn write(side: &Side, buffer: u64, count: u64, offset: i64) -> (u32, u64) {
    match side {
        Side::Volume { file: user_file, .. } => {
            let file = &user_file.file;
            if file.directory() {
                return (STATUS_FILE_IS_A_DIRECTORY, 0);
            }
            let offset = if offset == FILE_WRITE_TO_END_OF_FILE { file.size() } else { offset as u64 };
            let mut written = 0;
            if count != 0 {
                match file.volume().write(&file.volume_path(), offset, &guest::read_bytes(buffer, count as usize)) {
                    Ok(bytes) => written = bytes,
                    Err(error) => return (status_of(error), 0),
                }
                file.refresh();
            }
            if user_file.options & 0x30 != 0 {
                user_file.set_position(offset + written);
            }
            (0, written)
        }
        Side::Driver(file) => {
            let result = file.transfer(true, buffer, count as u32, offset, 0);
            (result.status, result.information)
        }
    }
}
