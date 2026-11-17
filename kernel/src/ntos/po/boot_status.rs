//! Boot status data (o arquivo bootstat.dat) pelo NtPowerInformation
//! PowerInformationInternal 0x1F (BootStatGet) e 0x20 (BootStatSet), de modo
//! usuário (ntoskrnl 19041: PopPowerInformationInternal rva 0x6f1b04,
//! PopBootStatGet 0x7c1810, PopBootStatSet 0x77f088 e as rotinas Rtl do
//! arquivo). O ntdll chega aqui pelo RtlGetSystemBootStatus e pelo
//! RtlSetSystemBootStatus; o lsasrv marca o boot bom (BsdLastBootSucceeded)
//! e o checkpoint de boot e ignora o resultado.
//!
//! - A entrada tem exatamente 0x18 bytes ({InternalType, Version, Count,
//!   pad, Items}), senão STATUS_INVALID_PARAMETER; Count zero também é
//!   inválido. Com saída, um ULONG por item volta no fim comum (Count * 4
//!   acima de 4 GB = STATUS_INTEGER_OVERFLOW): no Get, os bytes lidos; no
//!   Set, os bytes gravados (o último valor visto, que passa de um item ao
//!   seguinte).
//! - Os itens ({ULONG Class, PVOID Buffer, ULONG Size}, 0x18 bytes cada) são
//!   copiados do usuário (alinhamento 8); no Get cada Buffer é sondado para
//!   escrita, no Set para leitura.
//! - Sob o PopBootStatLock, o RtlLockBootStatusData abre o arquivo (o valor
//!   `OsBootstatPath` de `Control`, senão `\SystemRoot\bootstat.dat`) pelo
//!   ZwOpenFile (0x12019F, OBJ_KERNEL_HANDLE, FILE_SHARE_READ, síncrono) e
//!   lê o cache (o DWORD inicial é o tamanho dos dados, até 0x800). Sem o
//!   arquivo, o status da abertura volta ao chamador.
//! - O PopBootStatAccessCheck confere o descritor do arquivo contra o
//!   chamador (FILE_READ_DATA no Get, FILE_WRITE_DATA no Set, com o
//!   IopFileMapping).
//! - Cada item acha {deslocamento, tamanho} no RtlpBootStatusFields
//!   (classe de 0 a 0x11). No Get, o RtlGetSetBootStatusData lê o campo (do
//!   cache, ou do arquivo) e os bytes vão ao Buffer; um item que falha não
//!   interrompe os seguintes, e o status final é o do último. No Set, um
//!   Size menor que o campo dá STATUS_INVALID_PARAMETER; o valor é gravado
//!   no cache e no arquivo (com ZwFlushBuffersFile), o byte de checksum
//!   (classe 0xF) é ajustado pela diferença entre o valor antigo e o novo, e
//!   o gravador black box recebe o campo (categoria BSD).
//! - O RtlUnlockBootStatusData manda FSCTL_SET_COMPRESSION (formato nenhum)
//!   e fecha o arquivo quando a última referência sai.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::ntos::inc::types::{IoStatusBlock, NtStruct, ObjectAttributes, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SharedLock, SpinLock};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_REVISION_MISMATCH: u32 = 0xC000_0059;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// POWER_INFORMATION_LEVEL_INTERNAL PowerInternalBootStatGet e
/// PowerInternalBootStatSet.
pub const BOOT_STAT_GET: u32 = 0x1F;
pub const BOOT_STAT_SET: u32 = 0x20;

/// RtlpBootStatusFields: {deslocamento, tamanho} de cada classe.
const FIELDS: [(u32, u32); 18] = [(0x0, 4), (0x4, 4), (0x8, 1), (0x9, 1), (0xA, 1), (0xB, 1), (0xC, 1), (0x10, 0x20), (0x30, 1), (0x31, 1), (0x34, 4), (0x38, 4), (0x3C, 4), (0x40, 0x14), (0x58, 0x30), (0x32, 1), (0x88, 0x20), (0xA8, 4)];
/// A classe do byte de checksum.
const CHECKSUM_CLASS: u32 = 0xF;
/// O maior valor antigo que o RtlGetSetBootStatusData lê para o checksum.
const OLD_VALUE_LENGTH: usize = 0xB0;
/// O maior cache aceito pelo RtlInitializeBootStatDataCache.
const MAXIMUM_CACHE: u32 = 0x800;
/// FILE_READ_DATA e FILE_WRITE_DATA.
const FILE_READ_DATA: u32 = 1;
const FILE_WRITE_DATA: u32 = 2;
/// FSCTL_SET_COMPRESSION.
const FSCTL_SET_COMPRESSION: u64 = 0x9_C040;
/// O tamanho de um item da lista do pedido.
const ITEM_SIZE: u64 = 0x18;

/// O arquivo aberto (BootStatFileHandle, BootStatFileHandleAcquired,
/// BootStatReferenceCount, BootStatKeepHandleOpen e BootStatDataCache).
struct FileState {
    handle: u64,
    acquired: bool,
    references: u32,
    keep_open: bool,
    cache: Option<Vec<u8>>,
}

/// RtlpBootStatHandleLock (as aberturas e o fechamento fazem E/S sob ele) e
/// o estado, tomado só por instantes.
static HANDLE_LOCK: SharedLock = SharedLock::new();
static FILE: SpinLock<FileState> = SpinLock::new(FileState { handle: 0, acquired: false, references: 0, keep_open: false, cache: None });
/// PopBootStatLock.
static BOOT_STAT_LOCK: SharedLock = SharedLock::new();

/// Um bloco de kernel zerado.
fn zeroed(size: u64) -> Result<u64, u32> {
    let block = guest::alloc_bytes(size);
    if block == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(block, &vec![0u8; size as usize]);
    Ok(block)
}

/// Um serviço Zw* (PreviousMode KernelMode): o NTSTATUS.
fn zw(name: &str, arguments: &[u64]) -> u32 {
    crate::ntos::ps::previous_mode::with_kernel(|| crate::ntos::init::exports::invoke_handler(name, arguments)).ok().and_then(Result::ok).map_or(STATUS_UNSUCCESSFUL, |status| status as u32)
}

/// RtlBootStatusItemInfo.
fn item_info(class: u32) -> Result<(u32, u32), u32> {
    FIELDS.get(class as usize).copied().ok_or(STATUS_INVALID_PARAMETER)
}

/// ZwReadFile síncrono de `length` bytes em `offset`: os bytes lidos
/// (IoStatus.Information) ou o NTSTATUS.
fn read_file(handle: u64, offset: u64, length: u32) -> Result<Vec<u8>, u32> {
    let block = zeroed(0x20 + length as u64)?;
    let (io_status, byte_offset, buffer) = (block, block + 0x10, block + 0x20);
    guest::write64(byte_offset, offset);
    let status = zw("ZwReadFile", &[handle, 0, 0, 0, io_status, buffer, length as u64, byte_offset, 0]);
    // SAFETY: o IO_STATUS_BLOCK do bloco acima.
    let read = unsafe { IoStatusBlock::at(io_status) }.information.get().min(length as u64);
    let result = if status & 0x8000_0000 != 0 { Err(status) } else { Ok(guest::read_bytes(buffer, read as usize)) };
    guest::free_bytes(block);
    result
}

/// ZwWriteFile síncrono em `offset`: o NTSTATUS.
fn write_file(handle: u64, offset: u64, data: &[u8]) -> u32 {
    let Ok(block) = zeroed(0x20 + data.len() as u64) else { return STATUS_INSUFFICIENT_RESOURCES };
    let (io_status, byte_offset, buffer) = (block, block + 0x10, block + 0x20);
    guest::write64(byte_offset, offset);
    guest::write_bytes(buffer, data);
    let status = zw("ZwWriteFile", &[handle, 0, 0, 0, io_status, buffer, data.len() as u64, byte_offset, 0]);
    guest::free_bytes(block);
    status
}

/// ZwFlushBuffersFile.
fn flush_file(handle: u64) -> u32 {
    let Ok(io_status) = zeroed(0x10) else { return STATUS_INSUFFICIENT_RESOURCES };
    let status = zw("ZwFlushBuffersFile", &[handle, io_status]);
    guest::free_bytes(io_status);
    status
}

/// RtlpGetBootStatusPath: o `OsBootstatPath` de `Control`, senão o arquivo
/// do Windows (`\OSDataRoot\Windows\bootstat.dat` com separação de estado).
fn status_path() -> String {
    if let Some(value) = crate::ntos::cm::registry::read_value_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Control", "OsBootstatPath") {
        let units: Vec<u16> = value.data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
        return String::from_utf16_lossy(&units);
    }
    if crate::ntos::cm::state_separation::is_enabled().unwrap_or(false) {
        String::from("\\OSDataRoot\\Windows\\bootstat.dat")
    } else {
        String::from("\\SystemRoot\\bootstat.dat")
    }
}

/// RtlInitializeBootStatDataCache: o DWORD inicial dá o tamanho (1 a
/// 0x800) e os dados inteiros vão ao cache.
fn initialize_cache(handle: u64) -> u32 {
    if FILE.lock().cache.is_some() {
        return 0;
    }
    let size = match read_file(handle, 0, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        Ok(_) => return STATUS_UNSUCCESSFUL,
        Err(status) => return status,
    };
    if size == 0 || size > MAXIMUM_CACHE {
        return STATUS_UNSUCCESSFUL;
    }
    match read_file(handle, 0, size) {
        Ok(bytes) if bytes.len() == size as usize => {
            FILE.lock().cache = Some(bytes);
            0
        }
        Ok(_) => STATUS_UNSUCCESSFUL,
        Err(status) => status,
    }
}

/// RtlLockBootStatusData(&Handle): o handle do arquivo, aberto na primeira
/// referência.
fn lock_data() -> Result<u64, u32> {
    let _guard = HANDLE_LOCK.acquire_exclusive();
    {
        let mut file = FILE.lock();
        file.references += 1;
        if file.acquired {
            return Ok(file.handle);
        }
    }
    let units: Vec<u16> = status_path().encode_utf16().collect();
    let block = zeroed(0x80 + units.len() as u64 * 2 + 2)?;
    let (attributes, name, io_status, handle_cell, text) = (block, block + 0x30, block + 0x40, block + 0x50, block + 0x80);
    guest::write_bytes(text, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    // SAFETY: UNICODE_STRING e OBJECT_ATTRIBUTES dentro do bloco zerado.
    let string = unsafe { UnicodeString::at(name) };
    string.length.set(units.len() as u16 * 2);
    string.maximum_length.set(units.len() as u16 * 2);
    string.buffer.set(text);
    // SAFETY: idem.
    let object = unsafe { ObjectAttributes::at(attributes) };
    object.length.set(ObjectAttributes::SIZE as u32);
    object.object_name.set(name);
    object.attributes.set(0x2C0);
    let status = zw("ZwOpenFile", &[handle_cell, 0x12_019F, attributes, io_status, 1, 0x20]);
    let handle = guest::read64(handle_cell);
    guest::free_bytes(block);
    if status & 0x8000_0000 != 0 {
        let mut file = FILE.lock();
        file.handle = 0;
        file.references = 0;
        file.acquired = false;
        return Err(status);
    }
    {
        let mut file = FILE.lock();
        file.handle = handle;
        file.acquired = true;
    }
    let _ = initialize_cache(handle);
    Ok(handle)
}

/// RtlUnlockBootStatusData(Handle).
fn unlock_data(handle: u64) {
    let _guard = HANDLE_LOCK.acquire_exclusive();
    let (target, close) = {
        let mut file = FILE.lock();
        if file.references == 0 {
            return;
        }
        file.references -= 1;
        if file.acquired && (handle == 0 || (!file.keep_open && file.references == 0)) {
            let target = if handle == 0 { file.handle } else { handle };
            file.references = 0;
            file.handle = 0;
            file.acquired = false;
            (target, true)
        } else {
            (handle, false)
        }
    };
    if target == 0 {
        return;
    }
    if let Ok(block) = zeroed(0x20) {
        let (io_status, format) = (block, block + 0x10);
        let _ = zw("ZwFsControlFile", &[target, 0, 0, 0, io_status, FSCTL_SET_COMPRESSION, format, 2, 0, 0]);
        guest::free_bytes(block);
    }
    if close {
        FILE.lock().cache = None;
        let _ = zw("ZwClose", &[target]);
    }
}

/// RtlpRecordBootStatusData: o campo gravado vai ao gravador black box
/// (ZwPowerInformation 94, categoria BSD).
fn record(offset: u32, data: &[u8]) {
    let Ok(block) = zeroed(0x20 + data.len() as u64) else { return };
    guest::write_bytes(block + 0x20, data);
    guest::write64(block, block + 0x20);
    guest::write64(block + 8, data.len() as u64);
    guest::write64(block + 0x10, offset as u64);
    guest::write32(block + 0x18, 1);
    guest::write32(block + 0x1C, 1);
    let _ = crate::ntos::po::black_box::update_from_kernel(block, 0x20, 0, 0);
    guest::free_bytes(block);
}

/// RtlpGetSetBootStatusData(Handle, Get, Class, Buffer, Size): o NTSTATUS
/// e, no sucesso, o tamanho do campo. `capacity` é o Size do chamador;
/// `buffer` tem ao menos o campo quando ele cabe em `capacity`. No Get,
/// `buffer` recebe o campo; no Set, os primeiros bytes de `buffer` são
/// gravados.
fn get_set_field(handle: u64, get: bool, class: u32, buffer: &mut [u8], capacity: u32) -> (u32, Option<u32>) {
    let header = match read_file(handle, 0, 4) {
        Ok(bytes) if bytes.len() == 4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        Ok(_) => return (STATUS_UNSUCCESSFUL, None),
        Err(status) => return (status, None),
    };
    let (offset, size) = match item_info(class) {
        Ok(field) => field,
        Err(status) => return (status, None),
    };
    if offset as u64 + size as u64 > header as u64 {
        return (STATUS_REVISION_MISMATCH, None);
    }
    if capacity < size || buffer.len() < size as usize {
        return (STATUS_BUFFER_TOO_SMALL, None);
    }
    let range = offset as usize..(offset + size) as usize;
    let status = if get {
        let cached = {
            let file = FILE.lock();
            if file.acquired && file.handle == handle { file.cache.as_ref().and_then(|cache| cache.get(range.clone()).map(<[u8]>::to_vec)) } else { None }
        };
        match cached {
            Some(bytes) => {
                buffer[..size as usize].copy_from_slice(&bytes);
                0
            }
            None => match read_file(handle, offset as u64, size) {
                Ok(bytes) => {
                    buffer[..bytes.len()].copy_from_slice(&bytes);
                    0
                }
                Err(status) => status,
            },
        }
    } else {
        {
            let mut file = FILE.lock();
            if file.acquired && file.handle == handle {
                if let Some(cache) = file.cache.as_mut().and_then(|cache| cache.get_mut(range)) {
                    cache.copy_from_slice(&buffer[..size as usize]);
                }
            }
        }
        let mut status = write_file(handle, offset as u64, &buffer[..size as usize]);
        if status & 0x8000_0000 == 0 {
            status = flush_file(handle);
        }
        record(offset, &buffer[..size as usize]);
        status
    };
    if status & 0x8000_0000 != 0 { (status, None) } else { (status, Some(size)) }
}

/// RtlGetSetBootStatusData(Handle, Get, Class, Buffer, Size, &Returned): o
/// Set ajusta o checksum pela diferença entre o valor antigo e o novo.
fn get_set(handle: u64, get: bool, class: u32, buffer: &mut [u8], capacity: u32) -> (u32, Option<u32>) {
    if get {
        return get_set_field(handle, true, class, buffer, capacity);
    }
    if class == CHECKSUM_CLASS {
        return (STATUS_INVALID_PARAMETER, None);
    }
    let mut checksum = [0u8; 1];
    let (status, _) = get_set_field(handle, true, CHECKSUM_CLASS, &mut checksum, 1);
    if status & 0x8000_0000 != 0 {
        return (status, None);
    }
    let mut old = [0u8; OLD_VALUE_LENGTH];
    let (status, _) = get_set_field(handle, true, class, &mut old, OLD_VALUE_LENGTH as u32);
    if status & 0x8000_0000 != 0 {
        return (status, None);
    }
    let (status, written) = get_set_field(handle, false, class, buffer, capacity);
    if status & 0x8000_0000 != 0 {
        return (status, None);
    }
    let length = written.unwrap_or(0) as usize;
    let mut sum = checksum[0];
    for &byte in &old[..length] {
        sum = sum.wrapping_add(byte);
    }
    for &byte in &buffer[..length] {
        sum = sum.wrapping_sub(byte);
    }
    let (status, _) = get_set_field(handle, false, CHECKSUM_CLASS, &mut [sum], 1);
    (status, written)
}

/// PopBootStatAccessCheck(Handle, UserMode, DesiredAccess): o descritor do
/// arquivo contra o contexto do chamador, com o IopFileMapping.
fn access_check(handle: u64, desired: u32) -> u32 {
    use crate::ntos::init::exports::invoke_handler;
    let Ok(block) = zeroed(0x60) else { return STATUS_INSUFFICIENT_RESOURCES };
    let (object_cell, descriptor_cell, allocated_cell, granted, access_status, subject) = (block, block + 8, block + 0x10, block + 0x18, block + 0x20, block + 0x30);
    let call = |name: &str, arguments: &[u64]| invoke_handler(name, arguments).map_or(STATUS_UNSUCCESSFUL, |status| status as u32);
    let mut status = call("ObReferenceObjectByHandle", &[handle, 0, 0, 0, object_cell, 0]);
    if status & 0x8000_0000 == 0 {
        let object = guest::read64(object_cell);
        status = call("ObGetObjectSecurity", &[object, descriptor_cell, allocated_cell]);
        if status & 0x8000_0000 == 0 {
            let descriptor = guest::read64(descriptor_cell);
            let mapping = crate::ntos::io::object_types::file_object_generic_mapping();
            let _ = call("SeCaptureSubjectContext", &[subject]);
            let allowed = invoke_handler("SeAccessCheck", &[descriptor, subject, 0, desired as u64, 0, 0, mapping, 1, granted, access_status]).is_ok_and(|granted| granted & 0xFF != 0);
            let _ = call("SeReleaseSubjectContext", &[subject]);
            status = if allowed { 0 } else { guest::read32(access_status) };
            let _ = call("ObReleaseObjectSecurity", &[descriptor, guest::read8(allocated_cell) as u64]);
        }
        let _ = call("ObDereferenceObject", &[object]);
    }
    guest::free_bytes(block);
    status
}

/// Um item do pedido.
struct Item {
    class: u32,
    buffer: u64,
    size: u32,
}

/// A lista de itens copiada do usuário (alinhamento 8, dentro do espaço de
/// usuário).
fn capture_items(items: u64, count: u32) -> Result<Vec<Item>, u32> {
    let length = count as u64 * ITEM_SIZE;
    if items & 7 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if !crate::ntos::ps::user_probe::probe_user_read(items, length) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let bytes = guest::try_read_bytes(items, length as usize).map_err(|error| error.status)?;
    let word = |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8]));
    Ok((0..count as usize).map(|index| Item { class: word(index * 0x18) as u32, buffer: word(index * 0x18 + 8), size: word(index * 0x18 + 0x10) as u32 }).collect())
}

/// O corpo comum do PopBootStatGet e do PopBootStatSet de modo usuário,
/// depois da captura: a trava, o arquivo, o acesso e cada item. Devolve o
/// NTSTATUS e o valor por item.
fn run(items: &[Item], get: bool) -> Result<(u32, Vec<u32>), KernelError> {
    crate::ntos::ke::critical_region::enter_critical()?;
    let guard = BOOT_STAT_LOCK.acquire_exclusive();
    let mut per_item = vec![0u32; items.len()];
    let handle = match lock_data() {
        Ok(handle) => handle,
        Err(status) => {
            drop(guard);
            crate::ntos::ke::critical_region::leave_critical()?;
            return Ok((status, per_item));
        }
    };
    let mut status = access_check(handle, if get { FILE_READ_DATA } else { FILE_WRITE_DATA });
    if status & 0x8000_0000 == 0 {
        // O valor por item passa de um item ao seguinte quando o campo
        // falha (a célula única do NT).
        let mut last = 0u32;
        for (index, item) in items.iter().enumerate() {
            let (_, field_size) = match item_info(item.class) {
                Ok(field) => field,
                Err(failure) => {
                    status = failure;
                    break;
                }
            };
            if get {
                let mut buffer = vec![0u8; (item.size as usize).min(OLD_VALUE_LENGTH)];
                let (result, returned) = get_set(handle, true, item.class, &mut buffer, item.size);
                status = result;
                if let Some(returned) = returned {
                    last = returned;
                    if returned != 0 && guest::try_write_bytes(item.buffer, &buffer[..returned as usize]).is_err() {
                        status = STATUS_ACCESS_VIOLATION;
                        break;
                    }
                }
            } else {
                if item.size < field_size {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                let mut buffer = match guest::try_read_bytes(item.buffer, field_size as usize) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        status = error.status;
                        break;
                    }
                };
                let (result, written) = get_set(handle, false, item.class, &mut buffer, field_size);
                status = result;
                if let Some(written) = written {
                    last = written;
                }
            }
            per_item[index] = last;
        }
    }
    unlock_data(handle);
    drop(guard);
    crate::ntos::ke::critical_region::leave_critical()?;
    Ok((status, per_item))
}

/// PowerInternalBootStatGet e PowerInternalBootStatSet de modo usuário
/// sobre a entrada capturada: o NTSTATUS e, com saída, os bytes do ULONG de
/// cada item.
pub fn request(internal: u32, input: &[u8], has_output: bool) -> Result<Result<Vec<u8>, u32>, KernelError> {
    if input.len() != 0x18 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    let count = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
    if count == 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    if has_output && count as u64 * 4 > u32::MAX as u64 {
        return Ok(Err(STATUS_INTEGER_OVERFLOW));
    }
    let items_address = u64::from_le_bytes(input[0x10..0x18].try_into().unwrap_or([0; 8]));
    let items = match capture_items(items_address, count) {
        Ok(items) => items,
        Err(status) => return Ok(Err(status)),
    };
    let get = internal == BOOT_STAT_GET;
    // Get: cada Buffer é sondado para escrita; Set: para leitura.
    for item in &items {
        let valid = item.size == 0 || if get { crate::ntos::ps::user_probe::probe_user_write(item.buffer, item.size as u64) } else { crate::ntos::ps::user_probe::probe_user_read(item.buffer, item.size as u64) };
        if !valid {
            return Ok(Err(STATUS_ACCESS_VIOLATION));
        }
    }
    let (status, per_item) = run(&items, get)?;
    if status & 0x8000_0000 != 0 {
        return Ok(Err(status));
    }
    if !has_output {
        return Ok(Ok(Vec::new()));
    }
    Ok(Ok(per_item.iter().flat_map(|value| value.to_le_bytes()).collect()))
}
