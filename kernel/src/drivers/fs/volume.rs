//! Interface de volume montável no namespace — o contrato que o Object
//! Manager usava em `node.mount` (`exists`, `list`) e as operações de
//! arquivo que os serviços de arquivo do kernel (`zw`) usam sobre ele.
//! Os métodos opcionais têm padrão "não suportado", como a ausência do
//! método no volume original.

use alloc::string::String;
use alloc::vec::Vec;

use crate::rtl::KernelError;

const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;

/// Metadados de um arquivo do volume (`stat` do original).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeStat {
    pub reference: Option<u64>,
    pub sequence: u16,
    pub directory: bool,
    pub size: u64,
    pub allocated: u64,
    pub attributes: u32,
    pub ea_size: u32,
    pub need_ea: u16,
    pub times: Vec<u8>,
}

/// Sistema de arquivos montado sob um diretório do namespace.
pub trait FileSystem: Sync {
    /// Nome de diagnóstico do volume.
    fn name(&self) -> &str;
    /// Caminho no formato do volume (`/arquivo`).
    fn exists(&self, path: &str) -> bool;
    /// Todos os caminhos do volume.
    fn list(&self) -> Vec<String>;
    /// Os caminhos diretamente sob um diretório (`path/filho`). O padrão
    /// devolve a listagem plana; volumes com diretórios aninhados (NTFS)
    /// sobrescrevem para enumerar a subpasta certa.
    fn list_directory(&self, _path: &str) -> Vec<String> {
        self.list()
    }
    /// O volume aceita criação e escrita.
    fn writable(&self) -> bool {
        false
    }
    fn stat(&self, _path: &str) -> Option<VolumeStat> {
        None
    }
    fn read_bytes(&self, _path: &str) -> Option<Vec<u8>> {
        None
    }
    fn size(&self, path: &str) -> Option<u64> {
        self.stat(path).map(|stat| stat.size).or_else(|| self.read_bytes(path).map(|bytes| bytes.len() as u64))
    }
    fn read_range(&self, path: &str, offset: u64, length: u64) -> Result<Option<Vec<u8>>, KernelError> {
        Ok(self.read_bytes(path).map(|bytes| {
            let start = (offset as usize).min(bytes.len());
            let end = start.saturating_add(length as usize).min(bytes.len());
            bytes[start..end].to_vec()
        }))
    }
    fn write_at(&self, _path: &str, _offset: u64, _bytes: &[u8]) -> Result<u64, KernelError> {
        Err(KernelError::with_status("volume is read-only", STATUS_MEDIA_WRITE_PROTECTED))
    }
    /// Novo tamanho do arquivo; `None` = o volume não redimensiona.
    fn resize(&self, _path: &str, _size: u64) -> Option<Result<u64, KernelError>> {
        None
    }
    /// Cópia direta de um trecho para a memória física; `None` = sem suporte.
    fn copy_range_to_physical(&self, _path: &str, _offset: u64, _address: u64, _length: u64) -> Option<Result<(), KernelError>> {
        None
    }
    /// Cria vazio ou trunca (o `writeFileBytes(fs, path, [])` do original).
    fn truncate(&self, _path: &str) -> Result<(), KernelError> {
        Err(KernelError::with_status("volume is read-only", STATUS_MEDIA_WRITE_PROTECTED))
    }
    /// `None` = o volume não remove arquivos.
    fn remove(&self, _path: &str) -> Option<Result<bool, KernelError>> {
        None
    }
    /// Número de série (`volumeInformation().serial`).
    fn volume_serial(&self) -> Option<u64> {
        None
    }
    /// Identidade e capacidade do volume (FileFs*Information).
    fn volume_query(&self) -> Option<&dyn crate::drivers::fs::volume_information::VolumeQuery> {
        None
    }
    /// FSCTL do próprio sistema de arquivos (`fs.control`); `None` = sem suporte.
    fn control(&self, _path: &str, _code: u32, _input: &[u8], _output_length: u32) -> Option<Result<crate::drivers::fs::ntfs_control::ControlResult, KernelError>> {
        None
    }
    /// Consulta de EAs (`fs.queryEa`); `None` = sem suporte.
    fn query_ea(&self, _path: &str, _length: usize, _options: &crate::drivers::fs::extended_attributes::QueryOptions, _state: &mut crate::drivers::fs::extended_attributes::QueryState) -> Option<Result<crate::drivers::fs::extended_attributes::QueryResult, KernelError>> {
        None
    }
    /// Escrita de EAs (`fs.setEa`); `None` = sem suporte.
    fn set_ea(&self, _path: &str, _bytes: &[u8], _kernel_call: bool) -> Option<Result<(), KernelError>> {
        None
    }
}

/// Identidade de um volume (o `===` entre montagens do original).
pub fn same(left: &'static dyn FileSystem, right: &'static dyn FileSystem) -> bool {
    core::ptr::addr_eq(left as *const dyn FileSystem, right as *const dyn FileSystem)
}
