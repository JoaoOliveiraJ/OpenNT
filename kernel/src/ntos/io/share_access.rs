//! Compartilhamento de arquivos (SHARE_ACCESS) — I/O Manager (IoCheckShareAccess,
//! IoSetShareAccess, IoRemoveShareAccess, IoUpdateShareAccess).
//!
//! Os quatro exports clássicos são os casos sem LinkShareAccess dos
//! Io*LinkShareAccess* do ntoskrnl 10.0.19045 (IoCheckLinkShareAccess 0x6c7fe0,
//! IoSetLinkShareAccess 0x62de20, IoRemoveLinkShareAccessEx 0x62dd90,
//! IoUpdateLinkShareAccessEx 0x6c95f0). O FILE_OBJECT guarda os seis BOOLEANs
//! ReadAccess..SharedDelete; IOP_FILE_OBJECT_EXTENSION.FoExtFlags & 1
//! (IO_IGNORE_SHARE_ACCESS_CHECK) desliga a contabilidade. O SHARE_ACCESS é
//! do FS e protegido pelo lock dele (FCB), como no NT: acessos simples.

use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::extra_fs_ntfs::ShareAccess;
use crate::ntos::inc::types::{FileObject, IopFileObjectExtension, NtStruct};

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;

const FILE_READ_DATA_OR_EXECUTE: u32 = 0x21;
const FILE_WRITE_DATA_OR_APPEND: u32 = 0x06;
const DELETE: u32 = 0x1_0000;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_SHARE_DELETE: u32 = 4;

fn ignores_share_access(file: &FileObject) -> bool {
    let extension = file.file_object_extension.get();
    // SAFETY: FileObjectExtension, quando presente, é o IOP_FILE_OBJECT_EXTENSION do I/O Manager.
    extension != 0 && unsafe { IopFileObjectExtension::at(extension) }.fo_ext_flags.get() & 1 != 0
}

fn flag(cell: &Field<u8>) -> u32 {
    (cell.get() != 0) as u32
}

fn add(cell: &Field<u32>, delta: u32) {
    cell.set(cell.get().wrapping_add(delta));
}

fn has_access(file: &FileObject) -> bool {
    flag(&file.read_access) | flag(&file.write_access) | flag(&file.delete_access) != 0
}

/// IoCheckShareAccess(DesiredAccess, DesiredShareAccess, FileObject, ShareAccess, Update).
pub fn check(desired_access: u32, desired_share: u32, file: &FileObject, share: &ShareAccess, update: bool) -> u32 {
    let read = desired_access & FILE_READ_DATA_OR_EXECUTE != 0;
    let write = desired_access & FILE_WRITE_DATA_OR_APPEND != 0;
    let delete = desired_access & DELETE != 0;
    file.read_access.set(read as u8);
    file.write_access.set(write as u8);
    file.delete_access.set(delete as u8);
    if !(read || write || delete) {
        return STATUS_SUCCESS;
    }
    let shared_read = desired_share & FILE_SHARE_READ != 0;
    let shared_write = desired_share & FILE_SHARE_WRITE != 0;
    let shared_delete = desired_share & FILE_SHARE_DELETE != 0;
    file.shared_read.set(shared_read as u8);
    file.shared_write.set(shared_write as u8);
    file.shared_delete.set(shared_delete as u8);
    if ignores_share_access(file) {
        return STATUS_SUCCESS;
    }
    let open_count = share.open_count.get();
    let conflict = (read && share.shared_read.get() < open_count)
        || (share.readers.get() != 0 && !shared_read)
        || (write && share.shared_write.get() < open_count)
        || (share.writers.get() != 0 && !shared_write)
        || (delete && share.shared_delete.get() < open_count)
        || (share.deleters.get() != 0 && !shared_delete);
    if conflict {
        return STATUS_SHARING_VIOLATION;
    }
    if update {
        add(&share.open_count, 1);
        add(&share.deleters, delete as u32);
        add(&share.readers, read as u32);
        add(&share.writers, write as u32);
        add(&share.shared_read, shared_read as u32);
        add(&share.shared_write, shared_write as u32);
        add(&share.shared_delete, shared_delete as u32);
    }
    STATUS_SUCCESS
}

/// IoSetShareAccess(DesiredAccess, DesiredShareAccess, FileObject, ShareAccess).
pub fn set(desired_access: u32, desired_share: u32, file: &FileObject, share: &ShareAccess) {
    file.read_access.set((desired_access & FILE_READ_DATA_OR_EXECUTE != 0) as u8);
    file.write_access.set((desired_access & FILE_WRITE_DATA_OR_APPEND != 0) as u8);
    file.delete_access.set((desired_access & DELETE != 0) as u8);
    let ignore = ignores_share_access(file);
    let counters = [&share.open_count, &share.readers, &share.writers, &share.deleters, &share.shared_read, &share.shared_write];
    if !has_access(file) {
        for cell in counters {
            cell.set(0);
        }
        share.shared_delete.set(0);
        return;
    }
    file.shared_read.set((desired_share & FILE_SHARE_READ) as u8);
    file.shared_write.set(((desired_share >> 1) & 1) as u8);
    file.shared_delete.set(((desired_share >> 2) & 1) as u8);
    if ignore {
        // O NT zera os seis primeiros contadores e ainda grava SharedDelete.
        for cell in counters {
            cell.set(0);
        }
    } else {
        share.open_count.set(1);
        share.readers.set(flag(&file.read_access));
        share.writers.set(flag(&file.write_access));
        share.deleters.set(flag(&file.delete_access));
        share.shared_read.set(flag(&file.shared_read));
        share.shared_write.set(flag(&file.shared_write));
    }
    share.shared_delete.set(flag(&file.shared_delete));
}

/// IoRemoveShareAccess(FileObject, ShareAccess).
pub fn remove(file: &FileObject, share: &ShareAccess) {
    if ignores_share_access(file) || !has_access(file) {
        return;
    }
    let minus = |cell: &Field<u32>, present: bool| {
        if present {
            add(cell, u32::MAX);
        }
    };
    minus(&share.open_count, true);
    minus(&share.readers, flag(&file.read_access) != 0);
    minus(&share.writers, flag(&file.write_access) != 0);
    minus(&share.shared_read, flag(&file.shared_read) != 0);
    minus(&share.shared_write, flag(&file.shared_write) != 0);
    minus(&share.deleters, flag(&file.delete_access) != 0);
    minus(&share.shared_delete, flag(&file.shared_delete) != 0);
}

/// IoUpdateShareAccess(FileObject, ShareAccess).
pub fn update(file: &FileObject, share: &ShareAccess) {
    if ignores_share_access(file) || !has_access(file) {
        return;
    }
    add(&share.open_count, 1);
    add(&share.readers, flag(&file.read_access));
    add(&share.writers, flag(&file.write_access));
    add(&share.shared_read, flag(&file.shared_read));
    add(&share.shared_write, flag(&file.shared_write));
    add(&share.deleters, flag(&file.delete_access));
    add(&share.shared_delete, flag(&file.shared_delete));
}

// ---- LINK_SHARE_ACCESS (io-share-access-link) ------------------------------
//
// Os quatro Io*LinkShareAccess* do ntoskrnl 10.0.19045 (IoCheckLinkShareAccess
// 0x6c7fe0, IoSetLinkShareAccess 0x62de20, IoRemoveLinkShareAccessEx 0x62dd90,
// IoUpdateLinkShareAccessEx 0x6c95f0), que o ntfs.sys usa para contar a
// exclusão por hard link. Autocontido (só caminhos qualificados, nomes com
// prefixo `link_`/`LINK_`): os quatro exports clássicos do módulo são o caso
// LinkShareAccess NULL / flags 0 destes.
//
// Os contadores são protegidos pelo lock do FCB do chamador (o NT soma sem
// `lock`), então `get`/`set` simples, como no código real.
//
// IoShareAccessFlags (bits lidos pelo NT):
//   0x01 atualizar os contadores depois de checar;
//   0x02 não gravar os BOOLEANs do FILE_OBJECT;
//   0x04/0x08/0x10 não checar leitura/escrita/exclusão;
//   0x20 checar mesmo sem acesso de dados pedido;
//   0x40 checar exclusão no SHARE_ACCESS mesmo com LinkShareAccess;
//   0x80 não contar Deleters no LinkShareAccess;
//   0x80000000 tratar o pedido como se tivesse FILE_SHARE_READ.

const LINK_STATUS_SUCCESS: u32 = 0;
const LINK_STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const LINK_STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;

const LINK_UPDATE_SHARE_ACCESS: u32 = 0x01;
const LINK_DONT_UPDATE_FILE_OBJECT: u32 = 0x02;
const LINK_DONT_CHECK_READ: u32 = 0x04;
const LINK_DONT_CHECK_WRITE: u32 = 0x08;
const LINK_DONT_CHECK_DELETE: u32 = 0x10;
const LINK_FORCE_CHECK: u32 = 0x20;
const LINK_DELETE_FROM_SHARE_ACCESS: u32 = 0x40;
const LINK_DONT_COUNT_DELETERS: u32 = 0x80;
const LINK_FORCE_SHARED_READ: u32 = 0x8000_0000;

const LINK_READ_DATA_OR_EXECUTE: u32 = 0x21;
const LINK_WRITE_DATA_OR_APPEND: u32 = 0x06;
const LINK_DELETE: u32 = 0x1_0000;
const LINK_SHARE_READ: u32 = 1;
const LINK_SHARE_WRITE: u32 = 2;
const LINK_SHARE_DELETE: u32 = 4;
/// FoExtFlags & 1: IO_IGNORE_SHARE_ACCESS_CHECK na extensão do FILE_OBJECT.
const LINK_IGNORE_SHARE_ACCESS: u32 = 1;

/// Pedido de acesso/compartilhamento já decodificado.
struct LinkRequest {
    read: bool,
    write: bool,
    delete: bool,
    shared_read: bool,
    shared_write: bool,
    shared_delete: bool,
}

fn link_ignores_share_access(file: &crate::ntos::inc::types::FileObject) -> bool {
    let extension = file.file_object_extension.get();
    // SAFETY: a extensão de um FILE_OBJECT vivo é uma _IOP_FILE_OBJECT_EXTENSION.
    extension != 0 && unsafe { <crate::ntos::inc::types::IopFileObjectExtension as crate::ntos::inc::field::NtStruct>::at(extension) }.fo_ext_flags.get() & LINK_IGNORE_SHARE_ACCESS != 0
}

fn link_has_access(file: &crate::ntos::inc::types::FileObject) -> bool {
    file.read_access.get() | file.write_access.get() | file.delete_access.get() != 0
}

fn link_bump(cell: &crate::ntos::inc::field::Field<u32>, delta: u32) {
    cell.set(cell.get().wrapping_add(delta));
}

fn link_record_access(file: &crate::ntos::inc::types::FileObject, request: &LinkRequest) {
    file.read_access.set(request.read as u8);
    file.write_access.set(request.write as u8);
    file.delete_access.set(request.delete as u8);
}

/// Soma (`sign` = 1) ou subtrai (`sign` = u32::MAX) a abertura do FILE_OBJECT.
fn link_adjust_share(file: &crate::ntos::inc::types::FileObject, share: &crate::ntos::inc::types::extra_fs_ntfs::ShareAccess, sign: u32) {
    let flag = |cell: &crate::ntos::inc::field::Field<u8>| ((cell.get() != 0) as u32).wrapping_mul(sign);
    link_bump(&share.open_count, sign);
    link_bump(&share.readers, flag(&file.read_access));
    link_bump(&share.writers, flag(&file.write_access));
    link_bump(&share.shared_read, flag(&file.shared_read));
    link_bump(&share.shared_write, flag(&file.shared_write));
    link_bump(&share.deleters, flag(&file.delete_access));
    link_bump(&share.shared_delete, flag(&file.shared_delete));
}

/// Entrada (`sign` = 1) ou saída (`sign` = u32::MAX) no LinkShareAccess.
fn link_adjust_link(deleting: bool, shared_delete: bool, link: &crate::ntos::inc::types::extra_fs_ntfs::LinkShareAccess, flags: u32, sign: u32) {
    link_bump(&link.open_count, sign);
    if flags & LINK_DONT_COUNT_DELETERS == 0 {
        link_bump(&link.deleters, (deleting as u32).wrapping_mul(sign));
    }
    link_bump(&link.shared_deleters, (shared_delete as u32).wrapping_mul(sign));
}

/// Conflito de um tipo de acesso: pedido sem compartilhamento dos outros
/// abridores, ou abridores desse tipo sem o compartilhamento pedido.
fn link_conflict(requested: bool, shared_count: u32, open_count: u32, holders: u32, shared_requested: bool) -> bool {
    (requested && shared_count < open_count) || (holders != 0 && !shared_requested)
}

/// IoCheckLinkShareAccess(DesiredAccess, DesiredShareAccess, FileObject,
/// ShareAccess, LinkShareAccess, IoShareAccessFlags). ShareAccess só pode
/// ser NULL com leitura e escrita desligadas e a exclusão desligada ou
/// delegada ao link; o NT grava no FILE_OBJECT sem testar o ponteiro, então
/// um FILE_OBJECT NULL só é legal com 0x02. O conflito de exclusão é medido
/// no LinkShareAccess quando ele existe (salvo a flag 0x40).
pub fn check_link(
    desired_access: u32,
    desired_share: u32,
    file: Option<&crate::ntos::inc::types::FileObject>,
    share: Option<&crate::ntos::inc::types::extra_fs_ntfs::ShareAccess>,
    link: Option<&crate::ntos::inc::types::extra_fs_ntfs::LinkShareAccess>,
    flags: u32,
) -> u32 {
    let delete_on_link = link.is_some() && flags & LINK_DELETE_FROM_SHARE_ACCESS == 0;
    let unchecked = LINK_DONT_CHECK_READ | LINK_DONT_CHECK_WRITE;
    if share.is_none() && (flags & unchecked != unchecked || !(flags & LINK_DONT_CHECK_DELETE != 0 || delete_on_link)) {
        return LINK_STATUS_INVALID_PARAMETER;
    }
    let request = LinkRequest {
        read: desired_access & LINK_READ_DATA_OR_EXECUTE != 0,
        write: desired_access & LINK_WRITE_DATA_OR_APPEND != 0,
        delete: desired_access & LINK_DELETE != 0,
        shared_read: desired_share & LINK_SHARE_READ != 0 || flags & LINK_FORCE_SHARED_READ != 0,
        shared_write: desired_share & LINK_SHARE_WRITE != 0,
        shared_delete: desired_share & LINK_SHARE_DELETE != 0,
    };
    let recorded = file.filter(|_| flags & LINK_DONT_UPDATE_FILE_OBJECT == 0);
    if let Some(file) = recorded {
        link_record_access(file, &request);
    }
    if !(request.read || request.write || request.delete) && flags & LINK_FORCE_CHECK == 0 {
        return LINK_STATUS_SUCCESS;
    }
    if let Some(file) = recorded {
        file.shared_read.set(request.shared_read as u8);
        file.shared_write.set(request.shared_write as u8);
        file.shared_delete.set(request.shared_delete as u8);
    }
    if file.is_some_and(link_ignores_share_access) {
        return LINK_STATUS_SUCCESS;
    }
    let mut conflict = false;
    if let Some(share) = share {
        let open = share.open_count.get();
        if flags & LINK_DONT_CHECK_READ == 0 {
            conflict = link_conflict(request.read, share.shared_read.get(), open, share.readers.get(), request.shared_read);
        }
        if flags & LINK_DONT_CHECK_WRITE == 0 && !conflict {
            conflict = link_conflict(request.write, share.shared_write.get(), open, share.writers.get(), request.shared_write);
        }
        if flags & LINK_DONT_CHECK_DELETE == 0 && !conflict && !delete_on_link {
            conflict = link_conflict(request.delete, share.shared_delete.get(), open, share.deleters.get(), request.shared_delete);
        }
    }
    if let Some(link) = link.filter(|_| flags & LINK_DONT_CHECK_DELETE == 0 && !conflict && delete_on_link) {
        conflict = link_conflict(request.delete, link.shared_deleters.get(), link.open_count.get(), link.deleters.get(), request.shared_delete);
    }
    if conflict {
        return LINK_STATUS_SHARING_VIOLATION;
    }
    if flags & LINK_UPDATE_SHARE_ACCESS == 0 {
        return LINK_STATUS_SUCCESS;
    }
    // O NT soma sem testar ShareAccess; NULL (legal só sem checagem) não é tocado.
    if let Some(share) = share {
        link_bump(&share.open_count, 1);
        link_bump(&share.deleters, request.delete as u32);
        link_bump(&share.readers, request.read as u32);
        link_bump(&share.writers, request.write as u32);
        link_bump(&share.shared_read, request.shared_read as u32);
        link_bump(&share.shared_write, request.shared_write as u32);
        link_bump(&share.shared_delete, request.shared_delete as u32);
    }
    if let Some(link) = link {
        link_adjust_link(request.delete, request.shared_delete, link, flags, 1);
    }
    LINK_STATUS_SUCCESS
}

/// IoSetLinkShareAccess(DesiredAccess, DesiredShareAccess, FileObject,
/// ShareAccess, LinkShareAccess, IoShareAccessFlags): primeira abertura.
/// Sem acesso de dados, ou com FoExtFlags & 1, o SHARE_ACCESS inteiro fica
/// zerado (0x62df34: SharedDelete é gravado com o EAX já zerado) e o link
/// não muda.
pub fn set_link(
    desired_access: u32,
    desired_share: u32,
    file: &crate::ntos::inc::types::FileObject,
    share: &crate::ntos::inc::types::extra_fs_ntfs::ShareAccess,
    link: Option<&crate::ntos::inc::types::extra_fs_ntfs::LinkShareAccess>,
    flags: u32,
) {
    let clear = |share: &crate::ntos::inc::types::extra_fs_ntfs::ShareAccess| {
        for cell in [&share.open_count, &share.readers, &share.writers, &share.deleters, &share.shared_read, &share.shared_write, &share.shared_delete] {
            cell.set(0);
        }
    };
    let request = LinkRequest {
        read: desired_access & LINK_READ_DATA_OR_EXECUTE != 0,
        write: desired_access & LINK_WRITE_DATA_OR_APPEND != 0,
        delete: desired_access & LINK_DELETE != 0,
        shared_read: desired_share & LINK_SHARE_READ != 0 || flags & LINK_FORCE_SHARED_READ != 0,
        shared_write: desired_share & LINK_SHARE_WRITE != 0,
        shared_delete: desired_share & LINK_SHARE_DELETE != 0,
    };
    link_record_access(file, &request);
    let ignore = link_ignores_share_access(file);
    if !link_has_access(file) {
        clear(share);
        return;
    }
    file.shared_read.set(request.shared_read as u8);
    file.shared_write.set(request.shared_write as u8);
    file.shared_delete.set(request.shared_delete as u8);
    if ignore {
        clear(share);
        return;
    }
    share.open_count.set(1);
    share.readers.set(request.read as u32);
    share.writers.set(request.write as u32);
    share.deleters.set(request.delete as u32);
    share.shared_read.set(request.shared_read as u32);
    share.shared_write.set(request.shared_write as u32);
    share.shared_delete.set(request.shared_delete as u32);
    if let Some(link) = link {
        link_adjust_link(request.delete, request.shared_delete, link, flags, 1);
    }
}

/// IoRemoveLinkShareAccessEx(FileObject, ShareAccess, LinkShareAccess,
/// IoShareAccessFlags): a saída do arquivo e do link.
pub fn remove_link(
    file: &crate::ntos::inc::types::FileObject,
    share: &crate::ntos::inc::types::extra_fs_ntfs::ShareAccess,
    link: Option<&crate::ntos::inc::types::extra_fs_ntfs::LinkShareAccess>,
    flags: u32,
) {
    if link_ignores_share_access(file) || !link_has_access(file) {
        return;
    }
    link_adjust_share(file, share, u32::MAX);
    if let Some(link) = link {
        link_adjust_link(file.delete_access.get() != 0, file.shared_delete.get() != 0, link, flags, u32::MAX);
    }
}

/// IoUpdateLinkShareAccessEx(FileObject, ShareAccess, LinkShareAccess,
/// IoShareAccessFlags): mais uma abertura do arquivo e do link.
pub fn update_link(
    file: &crate::ntos::inc::types::FileObject,
    share: &crate::ntos::inc::types::extra_fs_ntfs::ShareAccess,
    link: Option<&crate::ntos::inc::types::extra_fs_ntfs::LinkShareAccess>,
    flags: u32,
) {
    if link_ignores_share_access(file) || !link_has_access(file) {
        return;
    }
    link_adjust_share(file, share, 1);
    if let Some(link) = link {
        link_adjust_link(file.delete_access.get() != 0, file.shared_delete.get() != 0, link, flags, 1);
    }
}
