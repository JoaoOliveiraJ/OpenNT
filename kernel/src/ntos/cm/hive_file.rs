//! A E/S de arquivo das hives (o CmpFileRead/CmpFileWrite/CmpFileSetSize
//! do NT).
//!
//! O Cm abre o primário e os logs de uma hive com ZwCreateFile num handle de
//! kernel (CmpOpenHiveFile, ntoskrnl 19041 rva 0x6ea5d8) e os mantém
//! abertos enquanto a hive está carregada:
//! - o primário de uma hive gravável com READ_CONTROL | FILE_READ_DATA |
//!   FILE_WRITE_DATA, sem compartilhamento, FILE_OPEN_IF quando a carga pode
//!   criar a hive (senão FILE_OPEN), CreateOptions FILE_NO_COMPRESSION |
//!   FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT |
//!   FILE_SEQUENTIAL_ONLY e FILE_ATTRIBUTE_NORMAL;
//! - os logs (`.LOG1` e `.LOG2`) com FILE_READ_DATA | FILE_WRITE_DATA, sem
//!   compartilhamento, FILE_OPEN_IF, FILE_NO_COMPRESSION |
//!   FILE_NO_INTERMEDIATE_BUFFERING | FILE_SEQUENTIAL_ONLY e
//!   FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM (os atributos de um log
//!   criado);
//! - numa carga só de leitura (REG_OPEN_READ_ONLY), FILE_READ_DATA com
//!   FILE_SHARE_READ e FILE_OPEN, para o primário e para os logs;
//! - com o token de acesso ao arquivo do NtLoadKey3, a abertura acontece
//!   impersonando o token (PsImpersonateClient no nível dele) e com
//!   OBJ_FORCE_ACCESS_CHECK; a impersonação anterior da thread volta depois;
//! - a segunda tentativa do CmpCmdHiveOpen abre impersonando uma cópia do
//!   token primário do próprio processo (RtlImpersonateSelfEx), sem
//!   OBJ_FORCE_ACCESS_CHECK.
//!
//! As leituras e escritas vão ao volume do FILE_OBJECT do handle. O
//! NtSaveKey e o NtRestoreKey recebem o handle de arquivo do chamador, que é
//! usado sem ser fechado.

use alloc::string::String;
use alloc::vec::Vec;

use crate::drivers::fs::volume::FileSystem;
use crate::drivers::fs::volume_files;
use crate::ntos::ps::user::file_objects::UserFile;
use crate::ntos::ps::user::state as user_state;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{IoStatusBlock, NtStruct, ObjectAttributes, UnicodeString};
use crate::ntos::io::file::system_file::SystemFile;
use crate::ntos::io::file::{query as query_file, zw as zw_files};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;

/// STATUS_REGISTRY_IO_FAILED, STATUS_INSUFFICIENT_RESOURCES,
/// STATUS_ACCESS_DENIED e STATUS_OBJECT_TYPE_MISMATCH.
pub const STATUS_REGISTRY_IO_FAILED: u32 = 0xC000_014D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;

/// FILE_OPEN, FILE_OPEN_IF e FILE_SYNCHRONOUS_IO_NONALERT |
/// FILE_NON_DIRECTORY_FILE.
pub const FILE_OPEN: u32 = 1;
pub const FILE_OPEN_IF: u32 = 3;
/// O Information do IO_STATUS_BLOCK de uma criação: o arquivo é novo.
pub const FILE_CREATED: u64 = 2;
const CREATE_OPTIONS: u32 = 0x60;
/// FILE_GENERIC_READ e FILE_GENERIC_READ | FILE_GENERIC_WRITE.
const READ_ACCESS: u32 = 0x0012_0089;
const READ_WRITE_ACCESS: u32 = 0x0012_019F;
/// As aberturas do CmpOpenHiveFile: acesso do primário gravável
/// (READ_CONTROL | FILE_READ_DATA | FILE_WRITE_DATA), dos logs graváveis e
/// das cargas só de leitura, FILE_SHARE_READ e as CreateOptions do primário
/// e dos logs.
const PRIMARY_ACCESS: u32 = 0x0002_0003;
const READ_CONTROL: u32 = 0x0002_0000;
const LOG_ACCESS: u32 = 0x3;
const READ_ONLY_ACCESS: u32 = 0x1;
const FILE_SHARE_READ: u32 = 1;
const PRIMARY_OPTIONS: u32 = 0xC024;
const LOG_OPTIONS: u32 = 0x800C;
/// FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM de um log criado.
const LOG_ATTRIBUTES: u32 = 0x6;
/// OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, e OBJ_FORCE_ACCESS_CHECK das
/// aberturas com o token de acesso ao arquivo.
const OPEN_ATTRIBUTES: u32 = 0x240;
const OBJ_FORCE_ACCESS_CHECK: u32 = 0x400;

/// Como uma carga abre os arquivos da hive.
#[derive(Clone, Copy, Default)]
pub struct OpenMode {
    /// REG_OPEN_READ_ONLY.
    pub read_only: bool,
    /// O token de impersonação referenciado do NtLoadKey3 (o
    /// CmExtendedParameterFileAccessToken) e o nível dele.
    pub token: Option<(u64, u32)>,
}

/// Executa `open` impersonando o token de acesso ao arquivo, com a
/// impersonação anterior da thread restaurada depois (o
/// PsReferenceImpersonationTokenEx e os dois PsImpersonateClient do
/// CmpOpenHiveFile); uma impersonação recusada é o resultado da abertura.
fn impersonating<T>(token: Option<(u64, u32)>, open: impl FnOnce() -> Result<T, u32>) -> Result<T, u32> {
    use crate::ntos::ps::{process, security};
    use crate::ntos::se::token::{thread as thread_tokens, tokens};
    let Some((token, level)) = token else { return open() };
    let thread = process::get_current_thread();
    let previous = thread_tokens::get(thread).filter(|previous| tokens::retain(previous.token).is_ok());
    let result = match security::impersonate_client(thread, token, false, false, level) {
        Ok(0) => {
            let result = open();
            let _ = match previous {
                Some(previous) => security::impersonate_client(thread, previous.token, previous.copy_on_open, previous.effective_only, previous.level),
                None => security::impersonate_client(thread, 0, false, false, 2),
            };
            result
        }
        Ok(status) => Err(status),
        Err(error) => Err(if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES }),
    };
    if let Some(previous) = previous {
        let _ = tokens::release(previous.token);
    }
    result
}

/// SecurityImpersonation e TokenImpersonation.
const SECURITY_IMPERSONATION: u32 = 2;
const TOKEN_TYPE_IMPERSONATION: u32 = 2;

/// RtlImpersonateSelfEx(SecurityImpersonation, 0, NULL) em volta de `open`
/// (a segunda tentativa do CmpCmdHiveOpen, rva 0x6036ed): a thread
/// impersona uma cópia de impersonação do token primário do processo, e a
/// impersonação anterior volta depois.
pub fn impersonating_self<T>(open: impl FnOnce() -> Result<T, u32>) -> Result<T, u32> {
    use crate::ntos::ps::{process, security};
    use crate::ntos::se::token::tokens;
    let status_of = |error: crate::rtl::KernelError| if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES };
    let primary = security::reference_primary_token(process::get_current_process()).map_err(status_of)?;
    let copy = tokens::duplicate(primary, SECURITY_IMPERSONATION, false, TOKEN_TYPE_IMPERSONATION);
    let _ = security::dereference_primary_token(primary);
    let copy = copy.map_err(status_of)?;
    let result = impersonating(Some((copy, SECURITY_IMPERSONATION)), open);
    let _ = tokens::release(copy);
    result
}

/// Argumentos do ZwCreateFile (bloco privado; o texto do nome vem depois).
#[repr(C)]
struct CreateRequest {
    attributes: ObjectAttributes,
    handle: Field<u64>,
    name: UnicodeString,
    io_status: IoStatusBlock,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for CreateRequest {}

/// Um arquivo de hive aberto.
pub struct HiveFile {
    /// Handle de kernel próprio (0 quando o handle é do chamador).
    handle: u64,
    backing: Backing,
}

/// Onde a E/S de um arquivo de hive vai.
#[derive(Clone)]
enum Backing {
    /// Arquivo do volume do kernel: a E/S vai ao FileSystem dele.
    Volume { volume: &'static dyn FileSystem, path: String },
    /// Arquivo de um file system real (o ntfs.sys do volume do sistema, com
    /// `--volume-sistema=ntfs.sys`): o ZwReadFile, o ZwWriteFile e o
    /// ZwSetInformationFile no handle de kernel (`io/file/system_file`), com
    /// o nome do FILE_OBJECT como identidade.
    Driver { handle: u64, name: String },
}

impl HiveFile {
    /// CmpOpenHiveFile: ZwCreateFile do nome NT com handle de kernel e sem
    /// compartilhamento.
    pub fn open(name: &str, disposition: u32, write: bool) -> Result<HiveFile, u32> {
        Self::open_with_disposition(name, disposition, write).map(|(file, _)| file)
    }

    /// [`HiveFile::open`] com o Information do IO_STATUS_BLOCK (FILE_OPENED
    /// ou [`FILE_CREATED`]).
    pub fn open_with_disposition(name: &str, disposition: u32, write: bool) -> Result<(HiveFile, u64), u32> {
        let access = if write { READ_WRITE_ACCESS } else { READ_ACCESS };
        Self::create(name, access, 0, disposition, CREATE_OPTIONS, OPEN_ATTRIBUTES)
    }

    /// O primário de uma carga (CmpOpenHiveFile com o índice 0): FILE_OPEN_IF
    /// quando a carga pode alocar a hive e é gravável, senão FILE_OPEN. O
    /// Information devolvido é [`FILE_CREATED`] também para um arquivo que já
    /// existia vazio (o EndOfFile 0 do ZwQueryInformationFile), que o
    /// CmpInitHiveFromFile trata como hive nova.
    pub fn open_primary(name: &str, allocate: bool, mode: OpenMode) -> Result<(HiveFile, u64), u32> {
        let (access, share, disposition) = if mode.read_only { (READ_ONLY_ACCESS, FILE_SHARE_READ, FILE_OPEN) } else { (PRIMARY_ACCESS, 0, if allocate { FILE_OPEN_IF } else { FILE_OPEN }) };
        let attributes = OPEN_ATTRIBUTES | if mode.token.is_some() { OBJ_FORCE_ACCESS_CHECK } else { 0 };
        let (file, information) = impersonating(mode.token, || Self::create(name, access, share, disposition, PRIMARY_OPTIONS, attributes))?;
        let information = if !mode.read_only && information != FILE_CREATED && file.size() == 0 { FILE_CREATED } else { information };
        Ok((file, information))
    }

    /// Um log de uma carga (`.LOG1` ou `.LOG2`, CmpOpenHiveFile com os
    /// índices 4 e 5): criado se faltar, com FILE_ATTRIBUTE_HIDDEN |
    /// FILE_ATTRIBUTE_SYSTEM; numa carga só de leitura, só o existente.
    pub fn open_log(name: &str, mode: OpenMode) -> Result<HiveFile, u32> {
        let (access, share, disposition) = if mode.read_only { (READ_ONLY_ACCESS, FILE_SHARE_READ, FILE_OPEN) } else { (LOG_ACCESS, 0, FILE_OPEN_IF) };
        let attributes = OPEN_ATTRIBUTES | if mode.token.is_some() { OBJ_FORCE_ACCESS_CHECK } else { 0 };
        let (file, information) = impersonating(mode.token, || Self::create(name, access, share, disposition, LOG_OPTIONS, attributes))?;
        if information == FILE_CREATED {
            file.add_attributes(LOG_ATTRIBUTES);
        }
        Ok(file)
    }

    /// A abertura só com READ_CONTROL (o CmpOpenHiveFile com o bit 8, sem
    /// acesso aos dados): o FILE_OBJECT de um arquivo que uma hive carregada
    /// mantém aberto sem compartilhamento, para o CmpIsThisSameFile.
    pub fn open_identity(name: &str) -> Result<HiveFile, u32> {
        Self::create(name, READ_CONTROL, 0, FILE_OPEN, PRIMARY_OPTIONS, OPEN_ATTRIBUTES).map(|(file, _)| file)
    }

    /// Os atributos que a criação do arquivo grava (o FileAttributes do
    /// ZwCreateFile), somados aos que o volume deu ao arquivo novo. Só no
    /// volume do kernel: num file system real eles vêm da própria criação.
    fn add_attributes(&self, attributes: u32) {
        let Backing::Volume { volume, path } = &self.backing else { return };
        let Some(ntfs) = crate::drivers::fs::volume_files::fixed_volume() else { return };
        if !crate::drivers::fs::volume::same(*volume, ntfs as &'static dyn FileSystem) {
            return;
        }
        let current = volume.stat(path).map_or(0, |stat| stat.attributes);
        let _ = ntfs.set_basic(path, None, current | attributes);
    }

    /// ZwCreateFile do nome NT num handle de kernel.
    fn create(name: &str, access: u32, share: u32, disposition: u32, options: u32, object_attributes: u32) -> Result<(HiveFile, u64), u32> {
        let units = name.encode_utf16().count() as u64;
        let block = guest::alloc_bytes(CreateRequest::SIZE + units * 2 + 2);
        if block == 0 {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        // SAFETY: bloco zerado recém-alocado; o texto vem logo depois dele.
        let request = unsafe { CreateRequest::at(block) };
        let text = block + CreateRequest::SIZE;
        guest_strings::write_wide_string(text, name);
        request.name.length.set(units as u16 * 2);
        request.name.maximum_length.set(units as u16 * 2 + 2);
        request.name.buffer.set(text);
        request.attributes.length.set(ObjectAttributes::SIZE as u32);
        request.attributes.object_name.set(request.name.address());
        request.attributes.attributes.set(object_attributes);
        // O ZwCreateFile do CmpOpenHiveFile roda em KernelMode, também numa
        // chamada de sistema de modo usuário (o NtLoadKey, o NtInitializeRegistry).
        let status = crate::ntos::ps::previous_mode::with_kernel(|| zw_files::create_kernel_file(request.handle.address(), access, request.attributes.address(), request.io_status.address(), share, disposition, options)).and_then(|status| status);
        let handle = request.handle.get();
        let information = request.io_status.information.get();
        guest::free_bytes(block);
        match status {
            Ok(0) => {}
            Ok(status) => return Err(status),
            Err(error) => return Err(if error.status != 0 { error.status } else { STATUS_REGISTRY_IO_FAILED }),
        }
        let file_object = zw_files::file_object_of_handle(handle);
        let backing = match zw_files::file_backing(file_object) {
            Some((volume, path)) => Backing::Volume { volume, path },
            None if crate::ntos::ob::objects::file::is_file(file_object) => Backing::Driver { handle, name: String::from(name) },
            None => {
                zw_files::close_file_entry(handle as u32);
                return Err(STATUS_OBJECT_TYPE_MISMATCH);
            }
        };
        Ok((HiveFile { handle, backing }, information))
    }

    /// O arquivo de um handle do chamador (IoConvertFileHandleToKernelHandle
    /// com o acesso pedido).
    pub fn from_handle(handle: u64, user: bool, access: u32) -> Result<HiveFile, u32> {
        // Arquivo de volume aberto pelo modo usuário (NtCreateFile/NtOpenFile).
        if user {
            if let Some(entry) = user_state::get_user_handle(handle) {
                if let Some(file) = entry.downcast::<UserFile>() {
                    if entry.access() & access != access {
                        return Err(STATUS_ACCESS_DENIED);
                    }
                    let volume: &'static dyn FileSystem = volume_files::fixed_volume().ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
                    return Ok(HiveFile { handle: 0, backing: Backing::Volume { volume, path: file.file.volume_path() } });
                }
            }
        }
        let selected = query_file::resolve(handle, user)?;
        if user && selected.access & access != access {
            return Err(STATUS_ACCESS_DENIED);
        }
        let (volume, path) = zw_files::file_backing(selected.pointer).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
        Ok(HiveFile { handle: 0, backing: Backing::Volume { volume, path } })
    }

    /// O mesmo arquivo sem a posse do handle (para a E/S fora das travas).
    pub fn alias(&self) -> HiveFile {
        HiveFile { handle: 0, backing: self.backing.clone() }
    }

    /// A identidade do arquivo, como o CmpIsThisSameFile compara os
    /// FILE_OBJECTs: o caminho no volume do kernel, ou o nome aberto num file
    /// system real.
    pub fn volume_path(&self) -> String {
        match &self.backing {
            Backing::Volume { path, .. } => path.clone(),
            Backing::Driver { name, .. } => name.clone(),
        }
    }

    /// O nome do FILE_OBJECT do handle próprio (o ObjectNameInformation do
    /// ZwQueryObject), sem o NUL. Um arquivo de um volume do kernel não tem
    /// QueryNameProcedure: o nome é o da montagem do volume mais o caminho
    /// (o papel do nome do dispositivo seguido do FileName).
    pub fn object_name(&self) -> Option<String> {
        if self.handle == 0 {
            return None;
        }
        let file_object = zw_files::file_object_of_handle(self.handle);
        if file_object == 0 {
            return None;
        }
        // O buffer de 0x200 bytes do CmpAddToHiveFileList.
        let buffer = guest::alloc_bytes(0x200);
        if buffer == 0 {
            return None;
        }
        let status = crate::ntos::ob::query_object::query_name_string(file_object, buffer, 0x200, 0);
        // SAFETY: OBJECT_NAME_INFORMATION montado no bloco próprio.
        let name = (status == 0).then(|| guest_strings::read_unicode_string(unsafe { UnicodeString::at(buffer) }.address())).filter(|name| !name.is_empty());
        guest::free_bytes(buffer);
        name.or_else(|| match &self.backing {
            Backing::Volume { volume, path } => crate::drivers::fs::native_file_name::from_volume(*volume, path),
            Backing::Driver { .. } => None,
        })
    }

    pub fn size(&self) -> u64 {
        match &self.backing {
            Backing::Volume { volume, path } => volume.size(path).unwrap_or(0),
            Backing::Driver { handle, .. } => SystemFile::borrowed(*handle).size().unwrap_or(0),
        }
    }

    /// CmpFileRead de `length` bytes a partir de `offset`.
    pub fn read_range(&self, offset: u64, length: u64) -> Result<Vec<u8>, u32> {
        let bytes = match &self.backing {
            Backing::Volume { volume, path } => volume.read_range(path, offset, length).ok().flatten(),
            Backing::Driver { handle, .. } => SystemFile::borrowed(*handle).read_at(offset, length).ok(),
        };
        match bytes {
            Some(bytes) if bytes.len() as u64 == length => Ok(bytes),
            _ => Err(STATUS_REGISTRY_IO_FAILED),
        }
    }

    /// CmpFileRead do arquivo inteiro.
    pub fn read(&self) -> Result<Vec<u8>, u32> {
        self.read_range(0, self.size())
    }

    /// CmpFileWrite.
    pub fn write(&self, offset: u64, data: &[u8]) -> Result<(), u32> {
        let written = match &self.backing {
            Backing::Volume { volume, path } => volume.write_at(path, offset, data).map_err(|error| alloc::format!("{error}")),
            Backing::Driver { handle, .. } => SystemFile::borrowed(*handle).write_at(offset, data).map_err(|status| alloc::format!("{status:#x}")),
        };
        match written {
            Ok(written) if written == data.len() as u64 => Ok(()),
            Ok(written) => {
                debug_print!("[cm] escrita de {} em {:#x}: {} de {} bytes", self.volume_path(), offset, written, data.len());
                Err(STATUS_REGISTRY_IO_FAILED)
            }
            Err(error) => {
                debug_print!("[cm] escrita de {} em {:#x} ({} bytes): {}", self.volume_path(), offset, data.len(), error);
                Err(STATUS_REGISTRY_IO_FAILED)
            }
        }
    }

    /// CmpFileSetSize.
    pub fn set_size(&self, size: u64) -> Result<(), u32> {
        if self.size() == size {
            return Ok(());
        }
        let resized = match &self.backing {
            Backing::Volume { volume, path } => match volume.resize(path, size) {
                Some(Ok(_)) => Ok(()),
                Some(Err(error)) => Err(alloc::format!("{error}")),
                None => Err(String::from("sem redimensionamento")),
            },
            Backing::Driver { handle, .. } => SystemFile::borrowed(*handle).set_size(size).map_err(|status| alloc::format!("{status:#x}")),
        };
        resized.map_err(|error| {
            debug_print!("[cm] tamanho de {} para {:#x}: {}", self.volume_path(), size, error);
            STATUS_REGISTRY_IO_FAILED
        })
    }

    /// CmpFileFlush: num file system real, o ZwFlushBuffersFile; no volume
    /// do kernel as escritas já foram ao disco.
    pub fn flush(&self) -> Result<(), u32> {
        match &self.backing {
            Backing::Volume { .. } => Ok(()),
            Backing::Driver { handle, .. } => SystemFile::borrowed(*handle).flush(),
        }
    }
}

impl Drop for HiveFile {
    fn drop(&mut self) {
        if self.handle != 0 {
            zw_files::close_file_entry(self.handle as u32);
        }
    }
}
