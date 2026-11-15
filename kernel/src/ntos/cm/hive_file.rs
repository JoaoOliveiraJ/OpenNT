//! A E/S de arquivo das hives (o CmpFileRead/CmpFileWrite/CmpFileSetSize
//! do NT).
//!
//! O Cm abre o primário e os logs de uma hive com ZwCreateFile num handle de
//! kernel, sem compartilhamento (CmpOpenHiveFile), e os mantém abertos
//! enquanto a hive está carregada. As leituras e escritas vão ao volume do
//! FILE_OBJECT do handle. O NtSaveKey e o NtRestoreKey recebem o handle de
//! arquivo do chamador, que é usado sem ser fechado.

use alloc::string::String;
use alloc::vec::Vec;

use crate::drivers::fs::volume::FileSystem;
use crate::drivers::fs::volume_files;
use crate::ntos::ps::user::file_objects::UserFile;
use crate::ntos::ps::user::state as user_state;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{IoStatusBlock, NtStruct, ObjectAttributes, UnicodeString};
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
const CREATE_OPTIONS: u32 = 0x60;
/// FILE_GENERIC_READ e FILE_GENERIC_READ | FILE_GENERIC_WRITE.
const READ_ACCESS: u32 = 0x0012_0089;
const READ_WRITE_ACCESS: u32 = 0x0012_019F;

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
    volume: &'static dyn FileSystem,
    path: String,
}

impl HiveFile {
    /// CmpOpenHiveFile: ZwCreateFile do nome NT com handle de kernel e sem
    /// compartilhamento.
    pub fn open(name: &str, disposition: u32, write: bool) -> Result<HiveFile, u32> {
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
        // OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE.
        request.attributes.attributes.set(0x240);
        let access = if write { READ_WRITE_ACCESS } else { READ_ACCESS };
        let status = zw_files::create_kernel_file(request.handle.address(), access, request.attributes.address(), request.io_status.address(), 0, disposition, CREATE_OPTIONS);
        let handle = request.handle.get();
        guest::free_bytes(block);
        match status {
            Ok(0) => {}
            Ok(status) => return Err(status),
            Err(error) => return Err(if error.status != 0 { error.status } else { STATUS_REGISTRY_IO_FAILED }),
        }
        let Some((volume, path)) = zw_files::file_backing(zw_files::file_object_of_handle(handle)) else {
            zw_files::close_file_entry(handle as u32);
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        };
        Ok(HiveFile { handle, volume, path })
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
                    return Ok(HiveFile { handle: 0, volume, path: file.file.volume_path() });
                }
            }
        }
        let selected = query_file::resolve(handle, user)?;
        if user && selected.access & access != access {
            return Err(STATUS_ACCESS_DENIED);
        }
        let (volume, path) = zw_files::file_backing(selected.pointer).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
        Ok(HiveFile { handle: 0, volume, path })
    }

    /// O mesmo arquivo sem a posse do handle (para a E/S fora das travas).
    pub fn alias(&self) -> HiveFile {
        HiveFile { handle: 0, volume: self.volume, path: self.path.clone() }
    }

    /// O caminho do arquivo no volume (a identidade do arquivo, como o
    /// CmpIsThisSameFile compara os FILE_OBJECTs).
    pub fn volume_path(&self) -> String {
        self.path.clone()
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
        name.or_else(|| crate::drivers::fs::native_file_name::from_volume(self.volume, &self.path))
    }

    pub fn size(&self) -> u64 {
        self.volume.size(&self.path).unwrap_or(0)
    }

    /// CmpFileRead do arquivo inteiro.
    pub fn read(&self) -> Result<Vec<u8>, u32> {
        let size = self.size();
        match self.volume.read_range(&self.path, 0, size) {
            Ok(Some(bytes)) if bytes.len() as u64 == size => Ok(bytes),
            _ => Err(STATUS_REGISTRY_IO_FAILED),
        }
    }

    /// CmpFileWrite.
    pub fn write(&self, offset: u64, data: &[u8]) -> Result<(), u32> {
        match self.volume.write_at(&self.path, offset, data) {
            Ok(written) if written == data.len() as u64 => Ok(()),
            _ => Err(STATUS_REGISTRY_IO_FAILED),
        }
    }

    /// CmpFileSetSize.
    pub fn set_size(&self, size: u64) -> Result<(), u32> {
        if self.size() == size {
            return Ok(());
        }
        match self.volume.resize(&self.path, size) {
            Some(Ok(_)) => Ok(()),
            _ => Err(STATUS_REGISTRY_IO_FAILED),
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
