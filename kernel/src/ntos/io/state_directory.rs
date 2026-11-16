//! Diretórios de estado dos dispositivos do PnP — IoGetDeviceDirectory.
//!
//! Comportamento conferido contra o ntoskrnl 19041:
//!   IoGetDeviceDirectory               rva 0x89e780
//!   PiGetStateRootPath                 rva 0x78111c
//!   PiBuildAndOpenDeviceDirectoryPath  rva 0x89ec30
//!   PiOpenDirectoryWithRoot            rva 0x89f5a0
//!   PiCreateDirectoryPath              rva 0x89ed64
//!
//! IoGetDeviceDirectory(Pdo, DirectoryType, Flags, Reserved, Handle*): PDO
//! NULL, Flags != 0, Reserved != NULL, saída NULL, PDO sem devnode ou com
//! InstancePath vazio, ou DirectoryType diferente de DeviceDirectoryData
//! (0) = STATUS_INVALID_PARAMETER. A raiz é a do RtlGetPersistedStateLocation
//! ("DriverState", tipo arquivo, padrão "\SystemRoot\System32\DriverState";
//! um mapeamento ausente vira STATUS_INTERNAL_ERROR) e o diretório é
//! `<raiz>\Devices\<nome>\Data`. O nome é o DEVPKEY_Device_StateDirectoryId
//! do devnode quando ele é DEVPROP_TYPE_STRING só com caracteres legais do
//! FAT (FsRtlLegalAnsiCharacterArray & FSRTL_FAT_LEGAL); o diretório é
//! aberto e criado se faltar. Sem a propriedade (STATUS_NOT_FOUND), com
//! outro tipo ou com caractere ilegal, o nome é o InstancePath com os
//! ilegais trocados por '#' (um caractere acima de 0x7F =
//! STATUS_INVALID_PARAMETER), aberto sem criar; se o caminho não existe
//! (STATUS_OBJECT_PATH_NOT_FOUND) o nome passa a ser um GUID novo
//! (ExUuidCreate, RtlStringFromGUID em maiúsculas), criado. Nos dois casos
//! a propriedade passa a ser o nome usado. A abertura é o ZwOpenFile
//! (FILE_LIST_DIRECTORY | SYNCHRONIZE, compartilhamento de leitura e
//! escrita, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
//! OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), o caminho precisa começar pela
//! raiz e só STATUS_OBJECT_PATH_NOT_FOUND leva à criação: a raiz e depois o
//! caminho inteiro pelo FILE_OPEN_IF, componente a componente quando um
//! intermediário falta (STATUS_OBJECT_TYPE_MISMATCH e
//! STATUS_INVALID_PARAMETER de um componente são tolerados).
//!
//! Diferença honesta: o diretório final não recebe o descritor de
//! segurança de PiAuGetStateDirectorySecurityObject, porque a criação de
//! arquivos do kernel do OpenNT não aplica descritores.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::persisted_state;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Guid, IoStatusBlock, ObjectAttributes, UnicodeString};
use crate::ntos::io::device_property;
use crate::ntos::io::file::zw;
use crate::ntos::io::pnp::devnode;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_data_layout::FSRTL_LEGAL_ANSI_CHARACTER_ARRAY;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_INTERNAL_ERROR: u32 = 0xC000_00E5;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
/// FILE_LIST_DIRECTORY | SYNCHRONIZE.
const DIRECTORY_ACCESS: u32 = 0x10_0001;
/// FILE_SHARE_READ | FILE_SHARE_WRITE.
const SHARE_READ_WRITE: u32 = 3;
const FILE_OPEN: u32 = 1;
const FILE_OPEN_IF: u32 = 3;
/// FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT.
const DIRECTORY_OPTIONS: u32 = 0x21;
/// OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE.
const KERNEL_CASE_INSENSITIVE: u32 = 0x240;
/// DeviceDirectoryData.
const DEVICE_DIRECTORY_DATA: u32 = 0;
/// FsRtlLegalAnsiCharacterArray: FSRTL_FAT_LEGAL.
const FSRTL_FAT_LEGAL: u8 = 0x01;
const DEVPROP_TYPE_STRING: u32 = 0x12;
/// DEVPKEY_Device_StateDirectoryId {83da6326-97a6-4088-9453-a1923f573b29}, 21.
pub const STATE_DIRECTORY_ID: [u8; 16] = [0x26, 0x63, 0xDA, 0x83, 0xA6, 0x97, 0x88, 0x40, 0x94, 0x53, 0xA1, 0x92, 0x3F, 0x57, 0x3B, 0x29];
pub const STATE_DIRECTORY_ID_PID: u32 = 21;

/// OBJECT_ATTRIBUTES, nome, IOSB e handle de uma abertura de diretório
/// (o texto do nome segue a estrutura).
#[repr(C)]
struct DirectoryOpen {
    attributes: ObjectAttributes,
    name: UnicodeString,
    io_status: IoStatusBlock,
    handle: Field<u64>,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for DirectoryOpen {}

/// ZwOpenFile (FILE_OPEN) ou ZwCreateFile (FILE_OPEN_IF) de um diretório
/// pelo caminho absoluto: (status, handle).
fn open_directory(path: &str, disposition: u32) -> Result<(u32, u64), KernelError> {
    let units: Vec<u16> = path.encode_utf16().collect();
    let block = guest::alloc_bytes(DirectoryOpen::SIZE + units.len() as u64 * 2 + 2);
    if block == 0 {
        return Ok((STATUS_INSUFFICIENT_RESOURCES, 0));
    }
    guest::write_bytes(block, &[0u8; DirectoryOpen::SIZE as usize]);
    // SAFETY: bloco zerado recém-alocado; o texto vem logo depois dele.
    let request = unsafe { DirectoryOpen::at(block) };
    let text = block + DirectoryOpen::SIZE;
    guest_strings::write_wide_string(text, path);
    request.name.length.set(units.len() as u16 * 2);
    request.name.maximum_length.set(units.len() as u16 * 2 + 2);
    request.name.buffer.set(text);
    request.attributes.length.set(ObjectAttributes::SIZE as u32);
    request.attributes.object_name.set(request.name.address());
    request.attributes.attributes.set(KERNEL_CASE_INSENSITIVE);
    let status = zw::create_kernel_file(request.handle.address(), DIRECTORY_ACCESS, request.attributes.address(), request.io_status.address(), SHARE_READ_WRITE, disposition, DIRECTORY_OPTIONS)?;
    let handle = if status & 0x8000_0000 == 0 { request.handle.get() } else { 0 };
    guest::free_bytes(block);
    Ok((status, handle))
}

fn close(handle: u64) {
    if handle != 0 {
        let _ = crate::ntos::ob::close::close(handle, Some(0));
    }
}

/// PiCreateDirectoryPath: o caminho pelo FILE_OPEN_IF; sem um intermediário,
/// cada prefixo terminado em '\' (a partir do terceiro caractere) é aberto
/// ou criado antes do caminho inteiro.
fn create_directory_path(path: &str) -> Result<(u32, u64), KernelError> {
    if path.len() < 2 || !path.starts_with('\\') || path.starts_with("\\\\") {
        return Ok((STATUS_INVALID_PARAMETER, 0));
    }
    let (status, handle) = open_directory(path, FILE_OPEN_IF)?;
    if status & 0x8000_0000 == 0 || status != STATUS_OBJECT_PATH_NOT_FOUND {
        return Ok((status, handle));
    }
    let units: Vec<u16> = path.encode_utf16().collect();
    for index in 2..units.len() {
        if units[index] != b'\\' as u16 {
            continue;
        }
        let prefix = String::from_utf16_lossy(&units[..index]);
        let (status, handle) = open_directory(&prefix, FILE_OPEN_IF)?;
        close(handle);
        if status & 0x8000_0000 != 0 && status != STATUS_OBJECT_TYPE_MISMATCH && status != STATUS_INVALID_PARAMETER {
            return Ok((status, 0));
        }
    }
    open_directory(path, FILE_OPEN_IF)
}

/// PiOpenDirectoryWithRoot: o caminho precisa começar pela raiz (sem caixa);
/// só STATUS_OBJECT_PATH_NOT_FOUND com `create` cria a raiz e o caminho.
fn open_with_root(root: &str, path: &str, create: bool) -> Result<(u32, u64), KernelError> {
    let prefix_matches = path.len() >= root.len() && path.chars().zip(root.chars()).all(|(left, right)| left.to_ascii_uppercase() == right.to_ascii_uppercase());
    if root.is_empty() || !prefix_matches {
        return Ok((STATUS_INVALID_PARAMETER, 0));
    }
    let (status, handle) = open_directory(path, FILE_OPEN)?;
    if status != STATUS_OBJECT_PATH_NOT_FOUND || !create {
        return Ok((status, handle));
    }
    let (status, root_handle) = create_directory_path(root)?;
    if status & 0x8000_0000 != 0 {
        return Ok((status, 0));
    }
    let result = create_directory_path(path);
    close(root_handle);
    result
}

/// PiBuildAndOpenDeviceDirectoryPath: `<raiz>\Devices\<nome>\Data`.
fn build_and_open(root: &str, name: &str, create: bool) -> Result<(u32, u64), KernelError> {
    let bytes = (root.encode_utf16().count() + name.encode_utf16().count()) * 2 + 0x14 + "Data".len() * 2;
    if bytes > 0xFFFE {
        return Ok((STATUS_BUFFER_OVERFLOW, 0));
    }
    open_with_root(root, &format!("{root}\\Devices\\{name}\\Data"), create)
}

/// PiGetStateRootPath("DriverState", "\SystemRoot\System32\DriverState", arquivo).
fn state_root_path() -> Result<Result<String, u32>, KernelError> {
    let source = "DriverState";
    let default = "\\SystemRoot\\System32\\DriverState";
    let block = guest::alloc_bytes(0x100);
    if block == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    guest_strings::write_wide_string(block, source);
    guest_strings::write_wide_string(block + 0x20, default);
    let required = block + 0xF8;
    guest::write32(required, 0);
    let first = persisted_state::query(block, 0, block + 0x20, 1, 0, 0, required);
    let result = if first & 0x8000_0000 == 0 {
        Err(STATUS_UNSUCCESSFUL)
    } else if first != STATUS_BUFFER_OVERFLOW {
        Err(first)
    } else {
        let length = guest::read32(required);
        let buffer = guest::alloc_bytes(length as u64 + 2);
        let second = persisted_state::query(block, 0, block + 0x20, 1, buffer, length, required);
        let text = if second == STATUS_OBJECT_NAME_NOT_FOUND {
            Err(STATUS_INTERNAL_ERROR)
        } else if second & 0x8000_0000 != 0 {
            Err(second)
        } else {
            Ok(guest_strings::read_wide_string(buffer))
        };
        guest::free_bytes(buffer);
        text
    };
    guest::free_bytes(block);
    Ok(result)
}

/// Caractere legal num nome de diretório (FsRtlLegalAnsiCharacterArray).
fn legal(unit: u16) -> bool {
    unit <= 0x7F && FSRTL_LEGAL_ANSI_CHARACTER_ARRAY[unit as usize] & FSRTL_FAT_LEGAL != 0
}

/// O DEVPKEY_Device_StateDirectoryId válido do devnode, ou `None` (o
/// caminho do InstancePath).
fn stored_directory_name(pdo: u64) -> Option<String> {
    let (property_type, bytes) = device_property::device_property_value(pdo, STATE_DIRECTORY_ID, STATE_DIRECTORY_ID_PID)?;
    if property_type != DEVPROP_TYPE_STRING || bytes.len() < 2 {
        return None;
    }
    let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    units.iter().all(|&unit| legal(unit)).then(|| String::from_utf16_lossy(&units))
}

/// IoGetDeviceDirectory: devolve o NTSTATUS e grava o handle em sucesso.
pub fn device_directory(pdo: u64, directory_type: u32, flags: u32, reserved: u64, output: u64) -> Result<u32, KernelError> {
    if pdo == 0 || flags != 0 || reserved != 0 || output == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let Some(node) = devnode::get(pdo) else { return Ok(STATUS_INVALID_PARAMETER) };
    if node.instance_path.is_empty() || directory_type != DEVICE_DIRECTORY_DATA {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let root = match state_root_path()? {
        Ok(root) => root,
        Err(status) => return Ok(status),
    };
    // SAFETY: o PHANDLE de saída do chamador de modo kernel.
    let output = unsafe { Field::<u64>::at(output) };
    if let Some(name) = stored_directory_name(pdo) {
        let (status, handle) = build_and_open(&root, &name, true)?;
        if status & 0x8000_0000 == 0 {
            output.set(handle);
        }
        return Ok(status);
    }
    let mut name = String::with_capacity(node.instance_path.len());
    for unit in node.instance_path.encode_utf16() {
        if unit > 0x7F {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        name.push(if legal(unit) { unit as u8 as char } else { '#' });
    }
    let (mut status, mut handle) = build_and_open(&root, &name, false)?;
    if status == STATUS_OBJECT_PATH_NOT_FOUND {
        let guid = guest::alloc_bytes(Guid::SIZE + UnicodeString::SIZE);
        crate::ntos::ex::uuid::create(guid);
        crate::ntos::rtl::guid::string_from_guid(guid, guid + Guid::SIZE);
        name = guest_strings::read_unicode_string(guid + Guid::SIZE);
        // SAFETY: o UNICODE_STRING que o RtlStringFromGUID acabou de preencher.
        guest::free_bytes(unsafe { UnicodeString::at(guid + Guid::SIZE) }.buffer.get());
        guest::free_bytes(guid);
        (status, handle) = build_and_open(&root, &name, true)?;
    }
    if status & 0x8000_0000 != 0 {
        return Ok(status);
    }
    let mut bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    bytes.extend_from_slice(&[0, 0]);
    device_property::store_device_property(pdo, STATE_DIRECTORY_ID, STATE_DIRECTORY_ID_PID, DEVPROP_TYPE_STRING, &bytes);
    output.set(handle);
    Ok(0)
}
