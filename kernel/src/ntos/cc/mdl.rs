//! MDLs sobre as páginas do cache — o papel do `cache\mdlsup.c` do NT.
//!
//! CcMdlRead/CcPrepareMdlWrite preparam o intervalo (leitura, ou
//! sobrescrita: páginas parciais lidas) e devolvem uma cadeia de MDLs, uma por
//! vista, descrevendo a memória da vista (não paginada, travada e mapeada:
//! MmGetSystemAddressForMdlSafe devolve o VA). Cada MDL segura uma referência
//! da vista até CcMdlReadComplete/CcMdlWriteComplete/CcMdlWriteAbort;
//! CcMdlWriteComplete marca sujo o que cada MDL cobre (e grava com
//! FO_WRITE_THROUGH).

use alloc::vec::Vec;

use super::cache_map::{self, CACHE};
use super::layout::{self, VIEW_SIZE};
use super::section_io::{self, Fill};
use super::status::{self, CcResult, Failure};
use super::{flush, vacb};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{IoStatusBlock, Mdl};
use crate::ntos::mm::guest_memory as guest;

/// Um MDL da cadeia (criado por `section_io::build_mdl` ou do file system).
fn mdl_at(address: u64) -> &'static Mdl {
    // SAFETY: elos da cadeia de MDLs que o Cc devolveu ao file system.
    unsafe { Mdl::at(address) }
}

fn write_io_status(io_status: u64, code: u32, information: u64) {
    if io_status != 0 {
        // SAFETY: PIO_STATUS_BLOCK de kernel do file system.
        let block = unsafe { IoStatusBlock::at(io_status) };
        block.status.set(code as i32);
        block.information.set(information);
    }
}

/// Monta a cadeia para [offset, end) e a anexa ao fim de `*chain`.
fn build_chain(file: u64, offset_pointer: u64, length: u32, chain: u64, io_status: u64, fill_for_write: bool) -> CcResult<()> {
    let base = cache_map::require_map(file)?;
    let offset = flush::large_integer(offset_pointer);
    let end = offset + length as u64;
    let fill = if fill_for_write { Fill::Overwrite { start: offset, end } } else { Fill::Read };
    let held = match section_io::prepare_range(base, offset, end, fill, true) {
        Ok(Some(held)) => held,
        Ok(None) => Vec::new(),
        Err(Failure::Raise(code)) => return Err(status::copy_failure(code)),
        Err(other) => return Err(other),
    };
    let mut created = Vec::new();
    for &(index, view_base) in &held {
        let view_start = vacb::view_offset(index);
        let (low, high) = (offset.max(view_start), end.min(view_start + VIEW_SIZE));
        let descriptor = section_io::build_mdl(view_base + (low - view_start), high - low, !fill_for_write);
        if descriptor == 0 {
            for &(made, made_index) in &created {
                guest::free_bytes(made);
                cache_map::release_view(base, made_index);
            }
            for &(index, _) in held.iter().skip(created.len()) {
                cache_map::release_view(base, index);
            }
            return Err(Failure::Raise(layout::status::INSUFFICIENT_RESOURCES));
        }
        created.push((descriptor, index));
    }
    {
        let mut cache = CACHE.lock();
        for &(descriptor, index) in &created {
            cache.mdls.insert(descriptor, (base, index));
        }
    }
    // Anexa ao fim da cadeia existente (`*MdlChain` e os `Next`).
    // SAFETY: PMDL* de saída do file system (memória de kernel).
    let mut tail: &Field<u64> = unsafe { Field::<u64>::at(chain) };
    while tail.get() != 0 {
        tail = &mdl_at(tail.get()).next;
    }
    for &(descriptor, _) in &created {
        tail.set(descriptor);
        tail = &mdl_at(descriptor).next;
    }
    write_io_status(io_status, layout::status::SUCCESS, length as u64);
    Ok(())
}

/// CcMdlRead(FileObject, FileOffset, Length, MdlChain, IoStatus).
pub fn mdl_read(file: u64, offset_pointer: u64, length: u32, chain: u64, io_status: u64) -> CcResult<()> {
    build_chain(file, offset_pointer, length, chain, io_status, false)
}

/// CcPrepareMdlWrite(FileObject, FileOffset, Length, MdlChain, IoStatus).
pub fn prepare_mdl_write(file: u64, offset_pointer: u64, length: u32, chain: u64, io_status: u64) -> CcResult<()> {
    build_chain(file, offset_pointer, length, chain, io_status, true)
}

/// Como a cadeia é devolvida.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Release {
    Read,
    WriteComplete,
    /// As páginas zeradas para a sobrescrita que não houve voltam a ser lidas.
    WriteAbort,
}

/// Solta cada MDL da cadeia; numa escrita concluída, marca sujo o que ele
/// cobre. Devolve o mapa e o intervalo sujo (para o write-through).
fn release_chain(chain: u64, mode: Release) -> Option<(u64, u64, u64)> {
    let mut range: Option<(u64, u64, u64)> = None;
    let mut current = chain;
    while current != 0 {
        let descriptor = mdl_at(current);
        let next = descriptor.next.get();
        let owner = CACHE.lock().mdls.remove(&current);
        if let Some((base, index)) = owner {
            if mode != Release::Read {
                let mut cache = CACHE.lock();
                if let Some(map) = cache.maps.get_mut(&base) {
                    if let Some(view) = map.views.get_mut(&index) {
                        let start = vacb::view_offset(index) + (descriptor.mapped_system_va.get() - view.base);
                        let end = start + descriptor.byte_count.get() as u64;
                        let mask = vacb::range_mask(index, start, end);
                        if mode == Release::WriteAbort {
                            view.valid &= !(mask & !view.dirty);
                        } else {
                            view.valid |= mask;
                            view.dirty |= mask;
                            map.valid_data_goal = map.valid_data_goal.max(end);
                            range = Some(match range {
                                Some((_, low, high)) => (base, low.min(start), high.max(end)),
                                None => (base, start, end),
                            });
                        }
                    }
                    cache_map::publish(map);
                }
            }
            guest::free_bytes(current);
            cache_map::release_view(base, index);
        }
        current = next;
    }
    range
}

/// CcMdlReadComplete(FileObject, MdlChain).
pub fn mdl_read_complete(_file: u64, chain: u64) {
    release_chain(chain, Release::Read);
}

/// CcMdlWriteComplete(FileObject, FileOffset, MdlChain).
pub fn mdl_write_complete(file: u64, _offset_pointer: u64, chain: u64) -> CcResult<()> {
    if let Some((base, start, end)) = release_chain(chain, Release::WriteComplete) {
        flush::write_through(file, base, start, end)?;
    }
    Ok(())
}

/// CcMdlWriteAbort(FileObject, MdlChain).
pub fn mdl_write_abort(_file: u64, chain: u64) {
    release_chain(chain, Release::WriteAbort);
}
