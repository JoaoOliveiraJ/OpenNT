//! Reparse points do NTFS.
//!
//! O reparse point de um arquivo é o atributo $REPARSE_POINT (0xC0) com o
//! buffer do FSCTL (REPARSE_DATA_BUFFER ou REPARSE_GUID_DATA_BUFFER), a
//! marca FILE_ATTRIBUTE_REPARSE_POINT no $STANDARD_INFORMATION e nas
//! informações duplicadas do $FILE_NAME (na entrada do diretório pai, com a
//! tag no lugar do tamanho de EA) e a entrada (tag, referência do arquivo)
//! no índice $R do `\$Extend\$Reparse`. A gravação mora em `ntfs_write`
//! (`Ntfs::store_reparse_point`); aqui ficam a leitura, a busca de uma
//! abertura e os três FSCTLs, conferidos com o ntfs.sys 10.0.19041:
//!
//! - FSCTL_SET_REPARSE_POINT (NtfsSetReparsePoint 0x23b520 e
//!   NtfsSetReparsePointInternal 0x23bd48): OutputBufferLength diferente de
//!   zero é STATUS_INVALID_PARAMETER; o handle precisa de FILE_WRITE_DATA ou
//!   FILE_WRITE_ATTRIBUTES (o Ccb, ou o FILE_OBJECT->WriteAccess), senão
//!   STATUS_ACCESS_DENIED; sem buffer de entrada, STATUS_INVALID_BUFFER_SIZE;
//!   o buffer passa pelo FsRtlValidateReparsePointBuffer; um MOUNT_POINT só
//!   num diretório (STATUS_NOT_A_DIRECTORY); num SYMLINK os 4 bits altos de
//!   Flags são zerados e um pedido de modo usuário exige o
//!   SeCreateSymbolicLinkPrivilege (STATUS_PRIVILEGE_NOT_HELD; o modo de
//!   desenvolvedor, que o dispensaria, não está ligado); um diretório só
//!   recebe um reparse point vazio, a menos que a tag admita diretório não
//!   vazio (STATUS_DIRECTORY_NOT_EMPTY); um SYMLINK num arquivo exige o
//!   $DATA vazio (STATUS_IO_REPARSE_DATA_INVALID); sobre um reparse point
//!   existente, outra tag é STATUS_IO_REPARSE_TAG_MISMATCH e, numa tag que
//!   não é da Microsoft, outro GUID é STATUS_REPARSE_ATTRIBUTE_CONFLICT; a
//!   mesma tag substitui o buffer. Information = 0.
//! - FSCTL_GET_REPARSE_POINT (NtfsGetReparsePoint 0x1274bc): InputBufferLength
//!   diferente de zero é STATUS_INVALID_PARAMETER; sem buffer de saída,
//!   STATUS_INVALID_USER_BUFFER; sem reparse point,
//!   STATUS_NOT_A_REPARSE_POINT; o buffer gravado é revalidado; cabe inteiro
//!   (Information = tamanho), ou, com pelo menos 0x1C bytes de saída, vai
//!   cortado com STATUS_BUFFER_OVERFLOW; menos que isso é
//!   STATUS_BUFFER_TOO_SMALL.
//! - FSCTL_DELETE_REPARSE_POINT (NtfsDeleteReparsePoint 0x23a3a4):
//!   OutputBufferLength diferente de zero, acesso e buffer ausente como no
//!   SET; o buffer tem 8 bytes (REPARSE_DATA_BUFFER) ou 0x18
//!   (REPARSE_GUID_DATA_BUFFER, obrigatório nas tags que não são da
//!   Microsoft) com ReparseDataLength 0 (senão STATUS_IO_REPARSE_DATA_INVALID);
//!   tag até 2 é STATUS_IO_REPARSE_TAG_INVALID; sem reparse point,
//!   STATUS_NOT_A_REPARSE_POINT; tag e GUID conferidos como no SET.
//!
//! Na abertura (NtfsIsReparseRequired 0x154854 e o
//! NtfsOpenAttributeInExistingFile 0x113640 → NtfsGetReparsePointValue
//! 0x14f9d8), um componente intermediário com reparse point sempre devolve
//! STATUS_REPARSE — exceto um diretório cuja tag admite diretório não vazio,
//! que o caminho atravessa —, e o último só sem FILE_OPEN_REPARSE_POINT; o
//! I/O Manager recebe o buffer e o comprimento do nome que sobra
//! (`ReparseHit`, o Reserved do REPARSE_DATA_BUFFER) e faz o resto
//! (`io/reparse.rs`).

use alloc::vec::Vec;

use super::ntfs::{find_attribute, u16_at, u32_at, Ntfs, Stat};
use super::ntfs_control::{result, ControlCaller, ControlResult};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

pub const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
pub const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;
pub const FSCTL_DELETE_REPARSE_POINT: u32 = 0x0009_00AC;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
const STATUS_INVALID_USER_BUFFER: u32 = 0xC000_00E8;
const STATUS_INVALID_BUFFER_SIZE: u32 = 0xC000_0206;
const STATUS_NOT_A_REPARSE_POINT: u32 = 0xC000_0275;
const STATUS_IO_REPARSE_TAG_INVALID: u32 = 0xC000_0276;
const STATUS_IO_REPARSE_TAG_MISMATCH: u32 = 0xC000_0277;
const STATUS_IO_REPARSE_DATA_INVALID: u32 = 0xC000_0278;
const STATUS_REPARSE_ATTRIBUTE_CONFLICT: u32 = 0xC000_02B2;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
/// FILE_WRITE_DATA, FILE_APPEND_DATA (o FILE_OBJECT->WriteAccess) e
/// FILE_WRITE_ATTRIBUTES.
const WRITE_ACCESS: u32 = 0x2 | 0x4 | 0x100;
/// SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (o 0x23 do NtfsPrivilegeCheck).
const SE_CREATE_SYMBOLIC_LINK_PRIVILEGE: u64 = 35;
/// Saída mínima de um GET cortado (o `cmp ecx, 0x1c` do NtfsGetReparsePoint).
const MINIMUM_PARTIAL_GET: u32 = 0x1C;
/// Os 4 bits altos de SYMLINK.Flags, que o NTFS zera (`and 0x0FFFFFFF`).
const SYMLINK_FLAGS_KEPT: u32 = 0x0FFF_FFFF;

/// O primeiro reparse point no caminho de uma abertura: o buffer gravado e
/// quantos componentes do caminho vêm depois dele (o nome que o volume não
/// analisou).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReparseHit {
    pub buffer: Vec<u8>,
    pub tail_components: usize,
}

fn microsoft(tag: u32) -> bool {
    tag & 0x8000_0000 != 0
}

/// O GUID de um REPARSE_GUID_DATA_BUFFER (bytes 8..24).
fn guid(buffer: &[u8]) -> &[u8] {
    buffer.get(8..24).unwrap_or(&[])
}

/// FsRtlValidateReparsePointBuffer sobre uma cópia no pool, como o ntfs.sys
/// a chama com o SystemBuffer do pedido.
fn validate(buffer: &[u8]) -> u32 {
    let pool = guest::alloc_bytes(buffer.len().max(8) as u64);
    if pool == 0 {
        return 0xC000_009A;
    }
    guest::write_bytes(pool, buffer);
    let status = crate::ntos::fsrtl::reparse::validate_reparse_point_buffer(buffer.len() as u32, pool);
    guest::free_bytes(pool);
    status
}

/// Tag cujo reparse point o caminho atravessa num diretório (o
/// FsRtlIsNonEmptyDirectoryReparsePointAllowed do NtfsIsReparseRequired).
fn traversable(tag: u32) -> bool {
    crate::ntos::fsrtl::reparse::is_non_empty_directory_reparse_point_allowed(tag)
}

impl Ntfs {
    /// O valor do $REPARSE_POINT de um registro (residente ou pelas runs);
    /// `None` sem o atributo.
    pub fn reparse_value(&self, record: &[u8]) -> Result<Option<Vec<u8>>, KernelError> {
        if find_attribute(record, 0xC0)?.is_none() {
            return Ok(None);
        }
        Ok(Some(self.read_data(record, 0xC0)?))
    }

    /// O buffer do reparse point de `path` (`None` sem reparse point).
    pub fn reparse_point(&self, path: &str) -> Result<Option<Vec<u8>>, KernelError> {
        let _shared = self.resource().acquire_shared();
        let Some(entry) = self.find(path)? else { return Ok(None) };
        let record = self.read_record(entry.reference)?;
        self.reparse_value(&record)
    }

    /// O primeiro componente de `path` que devolve STATUS_REPARSE numa
    /// abertura: um intermediário com reparse point (fora o diretório cuja
    /// tag o caminho atravessa) ou o último sem `open_reparse_point`
    /// (FILE_OPEN_REPARSE_POINT). A marca vem das informações duplicadas da
    /// entrada no diretório pai, como no Fcb do NTFS. Um componente que não
    /// existe, ou um intermediário que não é diretório, encerra a busca sem
    /// reparse: a abertura segue e devolve o erro de sempre.
    pub fn find_reparse(&self, path: &str, open_reparse_point: bool) -> Result<Option<ReparseHit>, KernelError> {
        let _shared = self.resource().acquire_shared();
        let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        let mut directory = 5u64;
        for (index, part) in parts.iter().enumerate() {
            let entries = match self.directory(directory) {
                Ok(entries) => entries,
                Err(error) if error.status == STATUS_NOT_A_DIRECTORY => return Ok(None),
                Err(error) => return Err(error),
            };
            let Some(entry) = entries.find(part) else { return Ok(None) };
            let last = index + 1 == parts.len();
            let marked = entry.value.len() >= 60 && u32_at(&entry.value, 56) & FILE_ATTRIBUTE_REPARSE_POINT != 0;
            if marked && !(last && open_reparse_point) {
                let record = self.read_record(entry.reference)?;
                if let Some(buffer) = self.reparse_value(&record)?.filter(|buffer| buffer.len() >= 8) {
                    let is_directory = u16_at(&record, 22) & 2 != 0;
                    if last || !(is_directory && traversable(u32_at(&buffer, 0))) {
                        return Ok(Some(ReparseHit { buffer, tail_components: parts.len() - index - 1 }));
                    }
                }
            }
            directory = entry.reference;
        }
        Ok(None)
    }

    /// FSCTL_SET/GET/DELETE_REPARSE_POINT em `path` (aberto, com `stat`).
    pub(super) fn reparse_control(&self, path: &str, stat: &Stat, code: u32, input: &[u8], output_length: u32, caller: &ControlCaller) -> Result<ControlResult, KernelError> {
        let status = |status: u32| Ok(result(status, Vec::new()));
        match code {
            FSCTL_GET_REPARSE_POINT => {
                if !input.is_empty() {
                    return status(STATUS_INVALID_PARAMETER);
                }
                if output_length == 0 {
                    return status(STATUS_INVALID_USER_BUFFER);
                }
                let Some(buffer) = self.reparse_point(path)? else { return status(STATUS_NOT_A_REPARSE_POINT) };
                let validated = validate(&buffer);
                if validated != 0 {
                    return status(validated);
                }
                if buffer.len() as u32 <= output_length {
                    return Ok(result(0, buffer));
                }
                if output_length < MINIMUM_PARTIAL_GET {
                    return status(STATUS_BUFFER_TOO_SMALL);
                }
                Ok(ControlResult { status: STATUS_BUFFER_OVERFLOW, information: output_length, bytes: buffer[..output_length as usize].to_vec() })
            }
            FSCTL_SET_REPARSE_POINT => {
                if output_length != 0 {
                    return status(STATUS_INVALID_PARAMETER);
                }
                if caller.access & WRITE_ACCESS == 0 {
                    return status(STATUS_ACCESS_DENIED);
                }
                if input.is_empty() {
                    return status(STATUS_INVALID_BUFFER_SIZE);
                }
                let validated = validate(input);
                if validated != 0 {
                    return status(validated);
                }
                let mut buffer = input.to_vec();
                let tag = u32_at(&buffer, 0);
                if tag == IO_REPARSE_TAG_MOUNT_POINT && !stat.directory {
                    return status(STATUS_NOT_A_DIRECTORY);
                }
                if tag == IO_REPARSE_TAG_SYMLINK {
                    let flags = u32_at(&buffer, 0x10) & SYMLINK_FLAGS_KEPT;
                    buffer[0x10..0x14].copy_from_slice(&flags.to_le_bytes());
                    if !crate::ntos::se::privilege::single_privilege_check(SE_CREATE_SYMBOLIC_LINK_PRIVILEGE, caller.user_mode as u32) {
                        return status(STATUS_PRIVILEGE_NOT_HELD);
                    }
                }
                if stat.directory && !traversable(tag) && self.list(path)?.is_some_and(|children| !children.is_empty()) {
                    return status(STATUS_DIRECTORY_NOT_EMPTY);
                }
                if tag == IO_REPARSE_TAG_SYMLINK && !stat.directory && stat.size != 0 {
                    return status(STATUS_IO_REPARSE_DATA_INVALID);
                }
                if let Some(existing) = self.reparse_point(path)?.filter(|existing| existing.len() >= 4) {
                    if u32_at(&existing, 0) != tag {
                        return status(STATUS_IO_REPARSE_TAG_MISMATCH);
                    }
                    if !microsoft(tag) && guid(&existing) != guid(&buffer) {
                        return status(STATUS_REPARSE_ATTRIBUTE_CONFLICT);
                    }
                }
                self.store_reparse_point(path, Some(&buffer))?;
                status(0)
            }
            _ => {
                if output_length != 0 {
                    return status(STATUS_INVALID_PARAMETER);
                }
                if caller.access & WRITE_ACCESS == 0 {
                    return status(STATUS_ACCESS_DENIED);
                }
                if input.is_empty() {
                    return status(STATUS_INVALID_BUFFER_SIZE);
                }
                if input.len() != 8 && input.len() != 0x18 {
                    return status(STATUS_IO_REPARSE_DATA_INVALID);
                }
                if u16_at(input, 4) != 0 {
                    return status(STATUS_IO_REPARSE_DATA_INVALID);
                }
                let tag = u32_at(input, 0);
                if tag <= 2 {
                    return status(STATUS_IO_REPARSE_TAG_INVALID);
                }
                if !microsoft(tag) && input.len() != 0x18 {
                    return status(STATUS_IO_REPARSE_DATA_INVALID);
                }
                let Some(existing) = self.reparse_point(path)?.filter(|existing| existing.len() >= 4) else { return status(STATUS_NOT_A_REPARSE_POINT) };
                if u32_at(&existing, 0) != tag {
                    return status(STATUS_IO_REPARSE_TAG_MISMATCH);
                }
                if !microsoft(tag) && guid(&existing) != guid(input) {
                    return status(STATUS_REPARSE_ATTRIBUTE_CONFLICT);
                }
                self.store_reparse_point(path, None)?;
                status(0)
            }
        }
    }
}
