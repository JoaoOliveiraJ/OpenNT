//! NtCreatePagingFile (rva 0x7b6cc0) e o MiCreatePagingFile (rva 0x7b6cfc)
//! do ntoskrnl 19041, na partição do sistema:
//!
//! - Priority: os 23 bits baixos têm de ser zero; o bit 31 não aceita os
//!   bits 30 e 25; o bit 23 só vale sozinho, e mesmo assim é
//!   STATUS_NOT_SUPPORTED depois da captura do nome. Os erros são
//!   STATUS_INVALID_PARAMETER_4.
//! - PreviousMode UserMode: SeCreatePagefilePrivilege habilitado
//!   (SeSinglePrivilegeCheck), senão STATUS_PRIVILEGE_NOT_HELD; o
//!   UNICODE_STRING e os dois LARGE_INTEGERs sondados com alinhamento 4.
//! - MinimumSize de 1 MB a 0xFFFFFFFE000 bytes (STATUS_INVALID_PARAMETER_2);
//!   MaximumSize até o mesmo teto e não menor que o mínimo
//!   (STATUS_INVALID_PARAMETER_3); o nome com 1 a 256 bytes
//!   (STATUS_OBJECT_NAME_INVALID), copiado para o pool.
//! - O arquivo: um descritor com DACL de FILE_ALL_ACCESS para os
//!   Administradores e o LocalSystem; IoCreateFile com handle de kernel,
//!   FILE_READ_DATA | FILE_WRITE_DATA | WRITE_DAC | SYNCHRONIZE, oculto e de
//!   sistema, FILE_SHARE_WRITE, FILE_SUPERSEDE, FILE_NO_INTERMEDIATE_BUFFERING |
//!   FILE_DELETE_ON_CLOSE | FILE_NO_COMPRESSION e IO_OPEN_PAGING_FILE |
//!   IO_MM_PAGING_FILE | IO_NO_PARAMETER_CHECKING; o ZwSetSecurityObject da
//!   DACL; o fim do arquivo no mínimo arredondado à página
//!   (FileEndOfFileInformation); o FILE_OBJECT referenciado; o volume tem
//!   de ser de um file system de disco, de rede ou DFS
//!   (STATUS_UNRECOGNIZED_VOLUME); nenhuma seção pode mapear o arquivo
//!   (MiCheckPageFileMapping, STATUS_INCOMPATIBLE_FILE_MAP); disquete é
//!   STATUS_FLOPPY_VOLUME (FileFsDeviceInformation); o FSCTL de tipo de
//!   arquivo de paginação (FsRtlIssueFileNotificationFsctl) e a primeira
//!   página zerada pela E/S de paginação (MiZeroPageFileFirstPage).
//! - MiCreatePagefile e MiInsertPageFileInList (`paging_file::insert`). O
//!   handle fica com o MMPAGING_FILE. O bit 31 de Priority faz o arquivo de
//!   troca de working sets (WsSwapPagefile), um só, fora do commit e da
//!   paginação comum.
//! - Quando o IoCreateFile falha, o arquivo pode já ser um arquivo de
//!   paginação: a segunda abertura (FILE_OPEN, FILE_WRITE_DATA |
//!   SYNCHRONIZE, compartilhamento de leitura e escrita) acha o arquivo na
//!   lista (STATUS_NOT_FOUND se não estiver); o mínimo não pode cair
//!   (STATUS_INVALID_PARAMETER_2) nem o máximo (STATUS_INVALID_PARAMETER_3).
//!
//! Diferenças declaradas: o PpPagePathAssign (a notificação de uso de
//! paginação à pilha PnP do volume) não existe no OpenNT; o crescimento de
//! um arquivo de paginação já na lista (MiExtendPagingFileMaximum e o
//! pedido de extensão do mínimo) dá STATUS_NOT_SUPPORTED; o dump de falha
//! no arquivo de paginação (IoInitializeCrashDump) e o armazenamento
//! comprimido (SmpSystemStoreCreate) ficam de fora.

use alloc::string::String;
use alloc::vec::Vec;

use super::NewPagingFile;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{DeviceObject, FileObject, IoStatusBlock, ObjectAttributes, SectionObjectPointers, UnicodeString};
use crate::ntos::init::exports::invoke_handler;
use crate::ntos::io::file::information;
use crate::ntos::io::object_types;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::pfn;
use crate::ntos::ps::{previous_mode, process_context};
use crate::ntos::se::privilege;
use crate::rtl::KernelError;

/// SE_CREATE_PAGEFILE_PRIVILEGE.
const SE_CREATE_PAGEFILE_PRIVILEGE: u64 = 15;
/// Maior tamanho de arquivo de paginação, em bytes.
const MAXIMUM_PAGE_FILE_BYTES: u64 = 0xFFF_FFFF_E000;
const MINIMUM_PAGE_FILE_BYTES: i64 = 0x10_0000;
const PAGE: u64 = map::PAGE_SIZE;

const STATUS_SUCCESS: u32 = 0;
const STATUS_PENDING: u32 = 0x103;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_INCOMPATIBLE_FILE_MAP: u32 = 0xC000_004D;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const STATUS_UNRECOGNIZED_VOLUME: u32 = 0xC000_014F;
const STATUS_FLOPPY_VOLUME: u32 = 0xC000_0164;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;

/// Os bits de Priority.
const PRIORITY_RESERVED: u32 = 0x7F_FFFF;
const PRIORITY_UNSUPPORTED: u32 = 0x80_0000;
const PRIORITY_WITH_SWAP_FORBIDDEN: u32 = 0x4200_0000;

/// FILE_READ_DATA | FILE_WRITE_DATA | WRITE_DAC | SYNCHRONIZE.
const CREATE_ACCESS: u64 = 0x14_0003;
/// FILE_WRITE_DATA | SYNCHRONIZE.
const REOPEN_ACCESS: u64 = 0x10_0002;
/// FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM.
const HIDDEN_SYSTEM: u64 = 6;
const FILE_SHARE_WRITE: u64 = 2;
const FILE_SHARE_READ_WRITE: u64 = 3;
const FILE_SUPERSEDE: u64 = 0;
const FILE_OPEN: u64 = 1;
/// FILE_NO_INTERMEDIATE_BUFFERING | FILE_DELETE_ON_CLOSE | FILE_NO_COMPRESSION.
const CREATE_OPTIONS: u64 = 0x9008;
/// FILE_NO_INTERMEDIATE_BUFFERING | FILE_NO_COMPRESSION.
const REOPEN_OPTIONS: u64 = 0x8008;
/// IO_OPEN_PAGING_FILE | IO_MM_PAGING_FILE | IO_NO_PARAMETER_CHECKING.
const CREATE_FILE_OPTIONS: u64 = 0x112;
/// OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE.
const KERNEL_ATTRIBUTES: u32 = 0x240;
/// FILE_ALL_ACCESS.
const FILE_ALL_ACCESS: u64 = 0x1F_01FF;
const DACL_SECURITY_INFORMATION: u64 = 4;
const FILE_END_OF_FILE_INFORMATION: u64 = 0x14;
const FILE_FS_DEVICE_INFORMATION: u64 = 4;
/// FILE_FS_DEVICE_INFORMATION.Characteristics: FILE_FLOPPY_DISKETTE.
const FILE_FLOPPY_DISKETTE: u32 = 4;
/// DEVICE_OBJECT.DeviceType aceitos: FILE_DEVICE_DISK_FILE_SYSTEM,
/// FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_DEVICE_DFS_FILE_SYSTEM e
/// FILE_DEVICE_DFS_VOLUME (a máscara 0x60000000100100).
const PAGING_DEVICE_TYPES: u64 = 0x0060_0000_0010_0100;
/// FSCTL_FILE_TYPE_NOTIFICATION, enviado como IRP_MJ_FILE_SYSTEM_CONTROL.
const FSCTL_FILE_TYPE_NOTIFICATION: u64 = 0x9_0204;
const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0x0D;
/// FILE_TYPE_NOTIFICATION_FLAG_USAGE_BEGIN.
const USAGE_BEGIN: u32 = 1;
/// FILE_TYPE_NOTIFICATION_GUID_PAGE_FILE.
const PAGE_FILE_GUID: [u8; 16] = [0xa1, 0x64, 0x0a, 0x0d, 0xfc, 0x38, 0xb8, 0x4d, 0x9f, 0xe7, 0x3f, 0x43, 0x52, 0xcd, 0x7c, 0x5c];

fn status_of(result: Result<u64, KernelError>) -> u32 {
    match result {
        Ok(value) => value as u32,
        Err(error) if error.status != 0 => error.status,
        Err(_) => 0xC000_0001,
    }
}

/// Um export do ntoskrnl chamado pelo kernel, com o NTSTATUS dele.
fn kernel_call(name: &str, arguments: &[u64]) -> u32 {
    status_of(invoke_handler(name, arguments))
}

/// Um Zw* com PreviousMode = KernelMode.
fn zw_call(name: &str, arguments: &[u64]) -> u32 {
    match previous_mode::with_kernel(|| invoke_handler(name, arguments)) {
        Ok(result) => status_of(result),
        Err(error) => status_of(Err(error)),
    }
}

/// NtCreatePagingFile(PageFileName, MinimumSize, MaximumSize, Priority).
pub fn nt_create_paging_file(name: u64, minimum: u64, maximum: u64, priority: u32) -> Result<u32, KernelError> {
    let mode = previous_mode::get()?;
    create_paging_file(name, minimum, maximum, mode, priority)
}

/// A captura de um ponteiro de usuário de `size` bytes alinhado a 4: o
/// ProbeForRead do serviço.
fn probe_user(pointer: u64, size: u64) -> Result<(), u32> {
    if pointer & 3 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if pointer.checked_add(size).is_none_or(|end| end > map::USER_ADDRESS_LIMIT) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(())
}

/// O que o serviço captura antes de tocar o arquivo.
struct Request {
    minimum: u64,
    maximum: u64,
    name: Vec<u16>,
    priority: u32,
}

fn capture(name_pointer: u64, minimum_pointer: u64, maximum_pointer: u64, user: bool, priority: u32) -> Result<Request, u32> {
    if user {
        probe_user(name_pointer, UnicodeString::SIZE)?;
        probe_user(maximum_pointer, 8)?;
        probe_user(minimum_pointer, 8)?;
    }
    let minimum = guest::try_read::<u64>(minimum_pointer).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    if minimum > MAXIMUM_PAGE_FILE_BYTES || (minimum as i64) < MINIMUM_PAGE_FILE_BYTES {
        return Err(STATUS_INVALID_PARAMETER_2);
    }
    let maximum = guest::try_read::<u64>(maximum_pointer).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    if maximum > MAXIMUM_PAGE_FILE_BYTES || (minimum as i64) > (maximum as i64) {
        return Err(STATUS_INVALID_PARAMETER_3);
    }
    let length = guest::try_read::<u16>(name_pointer).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let buffer = guest::try_read::<u64>(name_pointer + 8).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    if length.wrapping_sub(1) > 0xFF {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    if user && buffer.checked_add(length as u64).is_none_or(|end| end > map::USER_ADDRESS_LIMIT) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let bytes = guest::try_read_bytes(buffer, length as usize).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    Ok(Request { minimum, maximum, name: bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect(), priority })
}

/// MiCreatePagingFile(PageFileName, MinimumSize, MaximumSize, PreviousMode,
/// Priority, MiSystemPartition).
pub fn create_paging_file(name_pointer: u64, minimum_pointer: u64, maximum_pointer: u64, previous_mode: u8, priority: u32) -> Result<u32, KernelError> {
    if priority & PRIORITY_RESERVED != 0 || ((priority as i32) < 0 && priority & PRIORITY_WITH_SWAP_FORBIDDEN != 0) || (priority & PRIORITY_UNSUPPORTED != 0 && priority & !PRIORITY_UNSUPPORTED != 0) {
        return Ok(STATUS_INVALID_PARAMETER_4);
    }
    let user = previous_mode != 0;
    if user && !privilege::single_privilege_check(SE_CREATE_PAGEFILE_PRIVILEGE, previous_mode as u32) {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    let request = match capture(name_pointer, minimum_pointer, maximum_pointer, user, priority) {
        Ok(request) => request,
        Err(status) => return Ok(status),
    };
    if priority & PRIORITY_UNSUPPORTED != 0 {
        return Ok(STATUS_NOT_SUPPORTED);
    }
    let name = String::from_utf16_lossy(&request.name);
    // O handle do arquivo é de kernel e fica na tabela do System; o OpenNT
    // procura um handle de kernel na tabela do processo corrente, então a
    // parte do arquivo roda anexada ao System (o mesmo handle vale em
    // qualquer contexto no NT). Tudo o que ela usa já está no pool.
    let system = crate::ntos::ps::process::get_system_process();
    let status = Scratch::new().map_or(STATUS_INSUFFICIENT_RESOURCES, |scratch| process_context::with_process(system, || create_with(&scratch, &request, &name)).unwrap_or(STATUS_INSUFFICIENT_RESOURCES));
    crate::debug_print!("[mm] NtCreatePagingFile {} minimo {:#x} maximo {:#x} -> {:#x}", name, request.minimum, request.maximum, status);
    Ok(status)
}

/// A memória de kernel das estruturas que o serviço passa às rotinas do
/// I/O Manager e do Se.
struct Scratch {
    block: u64,
}

const SCRATCH_SIZE: u64 = 0x400;
// Deslocamentos no bloco.
const HANDLE: u64 = 0x0;
const STATUS_BLOCK: u64 = 0x10;
const ALLOCATION_SIZE: u64 = 0x20;
const END_OF_FILE: u64 = 0x28;
const FILE_OBJECT: u64 = 0x30;
const RETURNED: u64 = 0x38;
const DEVICE_INFORMATION: u64 = 0x40;
const NAME: u64 = 0x50;
const ATTRIBUTES: u64 = 0x60;
const DESCRIPTOR: u64 = 0x98;
const ADMINISTRATORS_SID: u64 = 0xC0;
const SYSTEM_SID: u64 = 0xD0;
const ACL: u64 = 0xE0;
const ACL_SIZE: u64 = 0x40;
const NOTIFICATION: u64 = 0x120;
const EVENT: u64 = 0x140;
const NAME_BUFFER: u64 = 0x200;

impl Scratch {
    fn new() -> Option<Self> {
        let block = guest::alloc_bytes(SCRATCH_SIZE);
        (block != 0).then_some(Self { block })
    }

    fn at(&self, offset: u64) -> u64 {
        self.block + offset
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        guest::free_bytes(self.block);
    }
}

/// Um SID de autoridade NT (S-1-5-...) no bloco.
fn write_sid(address: u64, subauthorities: &[u32]) {
    let mut bytes = alloc::vec![1u8, subauthorities.len() as u8, 0, 0, 0, 0, 0, 5];
    for value in subauthorities {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    guest::write_bytes(address, &bytes);
}

/// O descritor absoluto com a DACL dos Administradores e do LocalSystem
/// (RtlCreateSecurityDescriptor, RtlCreateAcl, RtlAddAccessAllowedAce,
/// RtlSetDaclSecurityDescriptor).
fn build_descriptor(scratch: &Scratch) -> u32 {
    write_sid(scratch.at(ADMINISTRATORS_SID), &[32, 544]);
    write_sid(scratch.at(SYSTEM_SID), &[18]);
    let descriptor = scratch.at(DESCRIPTOR);
    let acl = scratch.at(ACL);
    for status in [
        kernel_call("RtlCreateSecurityDescriptor", &[descriptor, 1]),
        kernel_call("RtlCreateAcl", &[acl, ACL_SIZE, 2]),
        kernel_call("RtlAddAccessAllowedAce", &[acl, 2, FILE_ALL_ACCESS, scratch.at(ADMINISTRATORS_SID)]),
        kernel_call("RtlAddAccessAllowedAce", &[acl, 2, FILE_ALL_ACCESS, scratch.at(SYSTEM_SID)]),
        kernel_call("RtlSetDaclSecurityDescriptor", &[descriptor, 1, acl, 0]),
    ] {
        if status & 0x8000_0000 != 0 {
            return status;
        }
    }
    STATUS_SUCCESS
}

/// IoCreateFile do arquivo de paginação no bloco: a criação (`reopen`
/// falso) ou a reabertura de um arquivo que já existe.
fn open(scratch: &Scratch, reopen: bool) -> u32 {
    let (access, share, disposition, options) = if reopen { (REOPEN_ACCESS, FILE_SHARE_READ_WRITE, FILE_OPEN, REOPEN_OPTIONS) } else { (CREATE_ACCESS, FILE_SHARE_WRITE, FILE_SUPERSEDE, CREATE_OPTIONS) };
    guest::write64(scratch.at(HANDLE), 0);
    kernel_call("IoCreateFile", &[scratch.at(HANDLE), access, scratch.at(ATTRIBUTES), scratch.at(STATUS_BLOCK), scratch.at(ALLOCATION_SIZE), HIDDEN_SYSTEM, share, disposition, options, 0, 0, 0, 0, CREATE_FILE_OPTIONS])
}

fn close_handle(scratch: &Scratch) {
    let handle = guest::read64(scratch.at(HANDLE));
    if handle != 0 {
        zw_call("ZwClose", &[handle]);
        guest::write64(scratch.at(HANDLE), 0);
    }
}

fn io_status(scratch: &Scratch) -> u32 {
    // SAFETY: o IO_STATUS_BLOCK do bloco.
    unsafe { IoStatusBlock::at(scratch.at(STATUS_BLOCK)) }.status.get() as u32
}

/// ObReferenceObjectByHandle(Handle, FILE_READ_DATA | FILE_WRITE_DATA,
/// IoFileObjectType, KernelMode, &FileObject, NULL).
fn reference_file(scratch: &Scratch, access: u64) -> Result<u64, u32> {
    let object_type = guest::read64(object_types::file_object_type());
    let status = kernel_call("ObReferenceObjectByHandle", &[guest::read64(scratch.at(HANDLE)), access, object_type, 0, scratch.at(FILE_OBJECT), 0]);
    if status & 0x8000_0000 != 0 {
        return Err(status);
    }
    Ok(guest::read64(scratch.at(FILE_OBJECT)))
}

fn dereference(object: u64) {
    kernel_call("ObfDereferenceObject", &[object]);
}

fn create_with(scratch: &Scratch, request: &Request, name: &str) -> u32 {
    // O nome capturado, no pool, com o MaximumLength = Length.
    let length = request.name.len() as u64 * 2;
    guest::write_bytes(scratch.at(NAME_BUFFER), &request.name.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    // SAFETY: estruturas dentro do bloco do serviço.
    let (unicode, attributes) = unsafe { (UnicodeString::at(scratch.at(NAME)), ObjectAttributes::at(scratch.at(ATTRIBUTES))) };
    unicode.length.set(length as u16);
    unicode.maximum_length.set(length as u16);
    unicode.buffer.set(scratch.at(NAME_BUFFER));
    let status = build_descriptor(scratch);
    if status != STATUS_SUCCESS {
        return status;
    }
    attributes.length.set(ObjectAttributes::SIZE as u32);
    attributes.root_directory.set(0);
    attributes.object_name.set(unicode.address());
    attributes.attributes.set(KERNEL_ATTRIBUTES);
    attributes.security_descriptor.set(scratch.at(DESCRIPTOR));
    attributes.security_quality_of_service.set(0);
    guest::write64(scratch.at(ALLOCATION_SIZE), request.minimum);
    guest::write64(scratch.at(END_OF_FILE), request.minimum.div_ceil(PAGE) * PAGE);
    let created = open(scratch, false);
    if created & 0x8000_0000 != 0 {
        return reopen_existing(scratch, request, name);
    }
    let status = finish_create(scratch, request, name);
    if status != STATUS_SUCCESS {
        close_handle(scratch);
    }
    status
}

/// O resto do MiCreatePagingFile depois de um IoCreateFile bem-sucedido.
fn finish_create(scratch: &Scratch, request: &Request, name: &str) -> u32 {
    let handle = guest::read64(scratch.at(HANDLE));
    if io_status(scratch) & 0x8000_0000 == 0 {
        let status = zw_call("ZwSetSecurityObject", &[handle, DACL_SECURITY_INFORMATION, scratch.at(DESCRIPTOR)]);
        if status & 0x8000_0000 != 0 {
            return status;
        }
    }
    if io_status(scratch) & 0x8000_0000 != 0 {
        return io_status(scratch);
    }
    let status = zw_call("ZwSetInformationFile", &[handle, scratch.at(STATUS_BLOCK), scratch.at(END_OF_FILE), 8, FILE_END_OF_FILE_INFORMATION]);
    if status & 0x8000_0000 != 0 {
        return status;
    }
    if io_status(scratch) & 0x8000_0000 != 0 {
        return io_status(scratch);
    }
    let file = match reference_file(scratch, 3) {
        Ok(file) => file,
        Err(status) => return status,
    };
    let status = check_and_insert(scratch, file, handle, request, name);
    // A referência do ObReferenceObjectByHandle volta; o handle segue
    // retendo o arquivo para o MMPAGING_FILE.
    dereference(file);
    status
}

/// Volume, mapeamentos, dispositivo, notificação, primeira página e a
/// inserção na lista.
fn check_and_insert(scratch: &Scratch, file: u64, handle: u64, request: &Request, name: &str) -> u32 {
    let device = information::related_device_object(file).unwrap_or(0);
    // SAFETY: o dispositivo do topo da pilha de um FILE_OBJECT vivo.
    let device_type = if device != 0 { unsafe { DeviceObject::at(device) }.device_type.get() as u64 } else { u64::MAX };
    if device_type > 0x36 || PAGING_DEVICE_TYPES & (1 << device_type) == 0 {
        return STATUS_UNRECOGNIZED_VOLUME;
    }
    // MiCheckPageFileMapping: nenhuma seção de dados ou de imagem do arquivo.
    // SAFETY: FILE_OBJECT referenciado.
    let pointers = unsafe { FileObject::at(file) }.section_object_pointer.get();
    if pointers != 0 {
        // SAFETY: SECTION_OBJECT_POINTERS do file system dono do arquivo.
        let section = unsafe { SectionObjectPointers::at(pointers) };
        if section.data_section_object.get() != 0 || section.image_section_object.get() != 0 {
            return STATUS_INCOMPATIBLE_FILE_MAP;
        }
    }
    let status = kernel_call("IoQueryVolumeInformation", &[file, FILE_FS_DEVICE_INFORMATION, 8, scratch.at(DEVICE_INFORMATION), scratch.at(RETURNED)]);
    if status & 0x8000_0000 != 0 {
        return status;
    }
    if guest::read32(scratch.at(DEVICE_INFORMATION) + 4) & FILE_FLOPPY_DISKETTE != 0 {
        return STATUS_FLOPPY_VOLUME;
    }
    notify_page_file(scratch, file, device);
    super::mark_creating(file, true);
    let zeroed = zero_first_page(file);
    super::mark_creating(file, false);
    if zeroed & 0x8000_0000 != 0 {
        return zeroed;
    }
    match super::insert(NewPagingFile { file_object: file, handle, name: String::from(name), minimum: request.minimum / PAGE, maximum: request.maximum / PAGE, working_set_swap: (request.priority as i32) < 0 }) {
        Ok(number) => {
            // O MMPAGING_FILE retém o FILE_OBJECT (MiCreatePagefile guarda o
            // ponteiro; a referência é a do handle, que fica aberto).
            crate::debug_print!("PAGEFILE_OK {} numero {} minimo {} MB maximo {} MB", name, number, request.minimum >> 20, request.maximum >> 20);
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// FsRtlIssueFileNotificationFsctl(FileObject, USAGE_BEGIN,
/// FILE_TYPE_NOTIFICATION_GUID_PAGE_FILE): o FSCTL_FILE_TYPE_NOTIFICATION ao
/// file system, sem olhar o resultado.
fn notify_page_file(scratch: &Scratch, file: u64, device: u64) {
    let input = scratch.at(NOTIFICATION);
    guest::write32(input, USAGE_BEGIN);
    guest::write32(input + 4, 1);
    guest::write_bytes(input + 8, &PAGE_FILE_GUID);
    let event = scratch.at(EVENT);
    kernel_call("KeInitializeEvent", &[event, 0, 0]);
    // O NT monta o IRP sem buffer e aponta o SystemBuffer para a entrada na
    // pilha; o IoBuildDeviceIoControlRequest do OpenNT sempre aloca (e
    // libera na conclusão) o SystemBuffer, então a entrada vai por ele.
    let irp = invoke_handler("IoBuildDeviceIoControlRequest", &[FSCTL_FILE_TYPE_NOTIFICATION, device, input, 0x18, 0, 0, 0, event, scratch.at(STATUS_BLOCK)]).unwrap_or(0);
    if irp == 0 {
        return;
    }
    // SAFETY: o IRP recém-montado; a próxima stack location é a do FSCTL.
    let packet = unsafe { crate::ntos::inc::types::Irp::at(irp) };
    // SAFETY: como acima.
    let stack = unsafe { crate::ntos::inc::types::IoStackLocation::at(packet.tail.overlay.current_stack_location.get() - crate::ntos::inc::types::IoStackLocation::SIZE) };
    stack.file_object.set(file);
    stack.major_function.set(IRP_MJ_FILE_SYSTEM_CONTROL);
    if kernel_call("IofCallDriver", &[device, irp]) == STATUS_PENDING {
        kernel_call("KeWaitForSingleObject", &[event, 0, 0, 0, 0]);
    }
}

/// MiZeroPageFileFirstPage: a página zero do arquivo gravada pela E/S de
/// paginação, com uma página zerada.
fn zero_first_page(file: u64) -> u32 {
    let frame = pfn::alloc_page();
    if frame == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    crate::hal::physical::zero(frame, PAGE as usize);
    let status = super::write_file_object(file, 0, &[frame]);
    pfn::free_page(frame);
    status
}

/// O IoCreateFile falhou: a reabertura acha o arquivo de paginação que já
/// está na lista.
fn reopen_existing(scratch: &Scratch, request: &Request, name: &str) -> u32 {
    let reopened = open(scratch, true);
    if reopened & 0x8000_0000 != 0 {
        return reopened;
    }
    let status = match reference_file(scratch, 3) {
        Ok(file) => {
            let status = match super::find_by_name(name) {
                None => STATUS_NOT_FOUND,
                Some((minimum, maximum, size)) => {
                    let (new_minimum, new_maximum) = (request.minimum / PAGE, request.maximum / PAGE);
                    if minimum > new_minimum {
                        STATUS_INVALID_PARAMETER_2
                    } else if maximum > new_maximum {
                        STATUS_INVALID_PARAMETER_3
                    } else if maximum == new_maximum && new_minimum <= size {
                        STATUS_SUCCESS
                    } else {
                        STATUS_NOT_SUPPORTED
                    }
                }
            };
            dereference(file);
            status
        }
        Err(status) => status,
    };
    close_handle(scratch);
    status
}
