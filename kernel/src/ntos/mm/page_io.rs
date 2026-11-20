//! E/S de paginação do Mm sobre frames: o MDL de paginação que descreve os
//! frames (o MiBuildPagingMdl / o MDL embutido no MMINPAGE_SUPPORT do NT) e
//! o IoPageRead ou o IoSynchronousPageWrite síncrono do FILE_OBJECT, com o
//! evento e o IO_STATUS_BLOCK do Mm (`io/paging_io`).
//!
//! Servem o arquivo de paginação (`paging_file`) e as seções de arquivos
//! servidos por um file system (`section/fsd_file`): IRP_MJ_READ/WRITE com
//! IRP_PAGING_IO | IRP_NOCACHE | IRP_SYNCHRONOUS_PAGING_IO ao dispositivo
//! do IoGetRelatedDeviceObject do arquivo.
//!
//! O MDL leva MDL_PAGES_LOCKED (e MDL_IO_PAGE_READ na leitura) e o vetor de
//! PFNs dos frames. Um frame só fica mapeado no sistema pelo mapa direto;
//! vários frames, que não precisam ser contíguos, ganham PTEs de sistema
//! (`system_ptes`) durante a E/S, com MappedSystemVa e
//! MDL_MAPPED_TO_SYSTEM_VA: o MmGetSystemAddressForMdlSafe de quem precisa
//! dos bytes (a correção de USA do NTFS, um filtro) devolve uma VA que cobre
//! todos os frames, e o DMA usa o vetor de PFNs.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{FileObject, IoStatusBlock, Kevent, LargeInteger, Mdl};
use crate::ntos::io::paging_io::{self, PagingRequest};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::mdl as mm_mdl;
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::system_ptes;

const PAGE: u64 = map::PAGE_SIZE;
const STATUS_PENDING: u32 = 0x103;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// MdlFlags dos MDLs de paginação.
const MDL_MAPPED_TO_SYSTEM_VA: i16 = 0x0001;
const MDL_PAGES_LOCKED: i16 = 0x0002;
const MDL_IO_PAGE_READ: i16 = 0x0040;

/// O MDL de paginação dos frames e a faixa de PTEs de sistema que ele usa
/// (0 com um frame só).
struct PagingMdl {
    descriptor: u64,
    system_va: u64,
}

impl Drop for PagingMdl {
    fn drop(&mut self) {
        if self.system_va != 0 {
            system_ptes::unmap(self.system_va);
        }
        if self.descriptor != 0 {
            guest::free_bytes(self.descriptor);
        }
    }
}

fn paging_mdl(frames: &[u64], read: bool) -> Option<PagingMdl> {
    let (base, system_va) = if frames.len() == 1 {
        (map::direct_map(frames[0]), 0)
    } else {
        let va = system_ptes::map_frames(frames, 0);
        if va == 0 {
            return None;
        }
        (va, va)
    };
    let descriptor = mm_mdl::create(0, base, frames.len() as u64 * PAGE);
    let owned = PagingMdl { descriptor, system_va };
    if descriptor == 0 {
        return None;
    }
    // SAFETY: MDL recém-criado por MmCreateMdl, com espaço para os PFNs.
    let mdl = unsafe { Mdl::at(descriptor) };
    for (index, &frame) in frames.iter().enumerate() {
        guest::write64(descriptor + Mdl::SIZE + index as u64 * 8, frame / PAGE);
    }
    mdl.process.set(0);
    mdl.mapped_system_va.set(base);
    let mut flags = MDL_PAGES_LOCKED | MDL_MAPPED_TO_SYSTEM_VA;
    if read {
        flags |= MDL_IO_PAGE_READ;
    }
    mdl.mdl_flags.set(flags);
    Some(owned)
}

/// IoPageRead (`read`) ou IoSynchronousPageWrite de `frames` em
/// `byte_offset` do arquivo, esperando a conclusão. Devolve o NTSTATUS
/// final (o do IO_STATUS_BLOCK, ou o da recusa do envio) e a contagem
/// transferida (Information).
pub fn transfer(file: u64, byte_offset: u64, frames: &[u64], read: bool) -> (u32, u64) {
    if frames.is_empty() {
        return (0, 0);
    }
    let Some(descriptor) = paging_mdl(frames, read) else { return (STATUS_INSUFFICIENT_RESOURCES, 0) };
    let event = guest::alloc_bytes(Kevent::SIZE);
    let status_block = guest::alloc_bytes(IoStatusBlock::SIZE);
    let position = guest::alloc_bytes(LargeInteger::SIZE);
    let release = || {
        for block in [event, status_block, position] {
            if block != 0 {
                guest::free_bytes(block);
            }
        }
    };
    if event == 0 || status_block == 0 || position == 0 {
        release();
        return (STATUS_INSUFFICIENT_RESOURCES, 0);
    }
    dispatcher::initialize_event(event, 0, false);
    // SAFETY: blocos recém-alocados dos tipos certos; o FILE_OBJECT é retido
    // por quem pede a E/S (a lista de arquivos de paginação, a seção).
    let (status_cell, offset_cell, mdl, file_body) = unsafe { (IoStatusBlock::at(status_block), LargeInteger::at(position), Mdl::at(descriptor.descriptor), FileObject::at(file)) };
    offset_cell.quad_part.set(byte_offset as i64);
    status_cell.status.set(STATUS_PENDING as i32);
    status_cell.information.set(0);
    let request = PagingRequest { file: file_body, descriptor: mdl, offset: offset_cell, event, io_status: status_cell };
    let issued = if read { paging_io::page_read(&request, 0, 0) } else { paging_io::synchronous_page_write(&request) };
    let status = match issued {
        Ok(STATUS_PENDING) => {
            dispatcher::wait_for_single_object(event, 0, 0, false);
            status_cell.status.get() as u32
        }
        Ok(status) if status & 0x8000_0000 != 0 => status,
        Ok(_) => status_cell.status.get() as u32,
        Err(error) => {
            if error.status != 0 {
                error.status
            } else {
                0xC000_0001
            }
        }
    };
    let information = if status & 0x8000_0000 == 0 { status_cell.information.get() } else { 0 };
    release();
    drop(descriptor);
    (status, information)
}
