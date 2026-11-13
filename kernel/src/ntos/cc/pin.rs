//! Mapear e fixar dados do cache, como no Cache Manager do NT.
//!
//! CcMapData devolve `vacb | 1` (só uma referência de vista, como o NT);
//! CcPinRead/CcPreparePinWrite/CcPinMappedData devolvem um BCB nativo
//! (`layout::Bcb`, com o prefixo PUBLIC_BCB: MappedLength/MappedFileOffset),
//! compartilhado pelos pins de um intervalo que ele cobre. Cada mapeamento ou
//! pin segura uma referência da vista; um BCB sujo sobrevive ao último unpin
//! até ser gravado (é ele que guarda os LSNs para
//! CcGetDirtyPages/CcFlushCacheToLsn).
//!
//! O intervalo pedido fica dentro de uma vista de 256 KB (o CcMapData do NT
//! usa só o VACB do início); o excedente é cortado no fim da vista.
//! MAP_NO_READ/PIN_NO_READ ainda leem as páginas ausentes quando há espera
//! (as vistas não têm paginação sob demanda). Os ERESOURCEs dos BCBs
//! (PIN_EXCLUSIVE) não são modelados: os recursos do FS serializam.

use core::sync::atomic::Ordering;

use super::cache_map::{self, BcbState, CACHE};
use super::layout::{self, pin_flags, Bcb, Obcb, PAGE_SIZE, VIEW_SIZE};
use super::section_io::{self, Fill};
use super::status::{CcResult, Failure};
use super::{flush, vacb};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::IoStatusBlock;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

/// (vista, fim cortado na vista, máscara de páginas) de um intervalo.
fn clip(offset: u64, length: u32) -> (u64, u64, u64) {
    let index = vacb::view_index(offset);
    let end = (offset + length.max(1) as u64).min(vacb::view_offset(index) + VIEW_SIZE);
    (index, end, vacb::range_mask(index, offset, end))
}

fn buffer_of(view_base: u64, index: u64, offset: u64) -> u64 {
    view_base + (offset - vacb::view_offset(index))
}

/// Parâmetro de saída `PVOID *` (Bcb, Buffer) de kernel do file system.
fn out_pointer(address: u64) -> &'static Field<u64> {
    // SAFETY: os parâmetros de saída do Cc vêm de memória de kernel do FS.
    unsafe { Field::<u64>::at(address) }
}

/// Um BCB devolvido ao file system (sem a marca `| 1` de mapeamento).
fn bcb_at(address: u64) -> &'static Bcb {
    // SAFETY: BCB alocado por `cache_map::new_native_bcb`, ainda pinado ou sujo.
    unsafe { Bcb::at(address) }
}

/// É um BCB (e não `vacb | 1` nem um OBCB)?
fn is_bcb(address: u64) -> bool {
    address & 1 == 0 && bcb_at(address).node_type_code.get() == layout::NTC_BCB
}

/// CcMapData(FileObject, FileOffset, Length, Flags, Bcb, Buffer).
pub fn map_data(file: u64, offset_pointer: u64, length: u32, flags: u32, bcb_out: u64, buffer_out: u64) -> CcResult<bool> {
    let base = cache_map::require_map(file)?;
    let offset = flush::large_integer(offset_pointer);
    let (index, _, mask) = clip(offset, length);
    let Some(view_base) = section_io::prepare_view(base, index, mask, Fill::Read, flags & pin_flags::WAIT != 0)? else { return Ok(false) };
    let vacb = {
        let mut cache = CACHE.lock();
        let Some(map) = cache.maps.get_mut(&base) else { return Err(Failure::Kernel(KernelError::new("cache map vanished while mapping"))) };
        let Some(view) = map.views.get_mut(&index) else { return Err(Failure::Kernel(KernelError::new("view vanished while mapped"))) };
        view.maps += 1;
        vacb::publish_active_count(view);
        let vacb = view.vacb;
        cache_map::publish(map);
        vacb
    };
    out_pointer(bcb_out).set(vacb | 1);
    out_pointer(buffer_out).set(buffer_of(view_base, index, offset));
    Ok(true)
}

/// Pin comum: BCB existente que cobre o intervalo (PinCount+1) ou um novo.
/// A referência de vista do `prepare_view` passa a ser a do pin.
fn pin_range(base: u64, index: u64, offset: u64, end: u64, view_base: u64) -> CcResult<u64> {
    let mut cache = CACHE.lock();
    let Some(map) = cache.maps.get_mut(&base) else { return Err(Failure::Kernel(KernelError::new("cache map vanished while pinning"))) };
    let existing = map.bcbs.iter().find(|(_, state)| state.view == index && state.offset <= offset && state.offset + state.length as u64 >= end).map(|(&address, _)| address);
    let address = match existing {
        Some(address) => address,
        None => {
            let length = (end - offset) as u32;
            let address = cache_map::new_native_bcb(map, offset, length, index, buffer_of(view_base, index, offset));
            if address == 0 {
                drop(cache);
                cache_map::release_view(base, index);
                return Err(Failure::Raise(layout::status::INSUFFICIENT_RESOURCES));
            }
            map.bcbs.insert(address, BcbState { offset, length, pins: 0, dirty: false, oldest_lsn: 0, newest_lsn: 0, view: index });
            address
        }
    };
    if let Some(state) = map.bcbs.get_mut(&address) {
        state.pins += 1;
        bcb_at(address).pin_count.atomic().store(state.pins, Ordering::SeqCst);
    }
    Ok(address)
}

/// Existe BCB que cubra o intervalo (PIN_IF_BCB)?
fn has_bcb(base: u64, index: u64, offset: u64, end: u64) -> bool {
    CACHE.lock().maps.get(&base).is_some_and(|map| map.bcbs.values().any(|state| state.view == index && state.offset <= offset && state.offset + state.length as u64 >= end))
}

/// CcPinRead(FileObject, FileOffset, Length, Flags, Bcb, Buffer).
pub fn pin_read(file: u64, offset_pointer: u64, length: u32, flags: u32, bcb_out: u64, buffer_out: u64) -> CcResult<bool> {
    let base = cache_map::require_map(file)?;
    let offset = flush::large_integer(offset_pointer);
    let (index, end, mask) = clip(offset, length);
    if flags & pin_flags::IF_BCB != 0 && !has_bcb(base, index, offset, end) {
        return Ok(false);
    }
    let Some(view_base) = section_io::prepare_view(base, index, mask, Fill::Read, flags & pin_flags::WAIT != 0)? else { return Ok(false) };
    let bcb = pin_range(base, index, offset, end, view_base)?;
    out_pointer(bcb_out).set(bcb);
    out_pointer(buffer_out).set(buffer_of(view_base, index, offset));
    Ok(true)
}

/// Marca sujo um BCB: páginas, Dirty, LSNs (Oldest = menor, Newest = maior,
/// LargestLSN do mapa) e ValidDataGoal = max(BeyondLastByte).
fn dirty_bcb(base: u64, address: u64, lsn: u64) {
    let mut cache = CACHE.lock();
    let Some(map) = cache.maps.get_mut(&base) else { return };
    let native_map = map.native();
    let Some(state) = map.bcbs.get_mut(&address) else { return };
    let native = bcb_at(address);
    if lsn != 0 {
        if state.oldest_lsn == 0 || lsn < state.oldest_lsn {
            state.oldest_lsn = lsn;
        }
        if state.newest_lsn == 0 || lsn > state.newest_lsn {
            state.newest_lsn = lsn;
        }
        native.oldest_lsn.quad_part.set(state.oldest_lsn as i64);
        native.newest_lsn.quad_part.set(state.newest_lsn as i64);
        native_map.largest_lsn.quad_part.atomic().fetch_max(lsn as i64, Ordering::SeqCst);
    }
    state.dirty = true;
    native.dirty.set(1);
    let (index, start, end) = (state.view, state.offset, state.offset + state.length as u64);
    if let Some(view) = map.views.get_mut(&index) {
        let mask = vacb::range_mask(index, start, end);
        view.dirty |= mask;
        view.valid |= mask;
    }
    map.valid_data_goal = map.valid_data_goal.max(end);
    cache_map::publish(map);
}

/// CcPreparePinWrite(FileObject, FileOffset, Length, Zero, Flags, Bcb, Buffer):
/// fixa para sobrescrever (páginas inteiras não são lidas), zera com `Zero`
/// e já marca o BCB sujo.
pub fn prepare_pin_write(file: u64, offset_pointer: u64, length: u32, zero: bool, flags: u32, bcb_out: u64, buffer_out: u64) -> CcResult<bool> {
    let base = cache_map::require_map(file)?;
    let offset = flush::large_integer(offset_pointer);
    let (index, end, mask) = clip(offset, length);
    let Some(view_base) = section_io::prepare_view(base, index, mask, Fill::Overwrite { start: offset, end }, flags & pin_flags::WAIT != 0)? else { return Ok(false) };
    let buffer = buffer_of(view_base, index, offset);
    if zero {
        vacb::zero_bytes(buffer, end - offset);
    }
    let bcb = pin_range(base, index, offset, end, view_base)?;
    dirty_bcb(base, bcb, 0);
    out_pointer(bcb_out).set(bcb);
    out_pointer(buffer_out).set(buffer);
    Ok(true)
}

/// CcPinMappedData(FileObject, FileOffset, Length, Flags, Bcb): troca o
/// mapeamento `*Bcb` (de CcMapData) por um pin do mesmo intervalo.
pub fn pin_mapped_data(file: u64, offset_pointer: u64, length: u32, flags: u32, bcb_inout: u64) -> CcResult<bool> {
    let base = cache_map::require_map(file)?;
    let offset = flush::large_integer(offset_pointer);
    let (index, end, mask) = clip(offset, length);
    let Some(view_base) = section_io::prepare_view(base, index, mask, Fill::Read, flags & pin_flags::WAIT != 0)? else { return Ok(false) };
    let bcb = pin_range(base, index, offset, end, view_base)?;
    let slot = out_pointer(bcb_inout);
    let previous = slot.get();
    slot.set(bcb);
    if previous != 0 {
        unpin_data(previous)?;
    }
    Ok(true)
}

/// CcSetDirtyPinnedData(Bcb, Lsn). Um mapeamento (`vacb | 1`) ou outro nó
/// é o bugcheck CACHE_MANAGER do NT.
pub fn set_dirty_pinned_data(bcb: u64, lsn_pointer: u64) -> CcResult<()> {
    if !is_bcb(bcb) {
        crate::ntos::ke::bugcheck::raise_bug_check(0x34, 0xEDA, 0xFFFF_FFFF_C000_0420, 0, 0);
    }
    let lsn = if lsn_pointer != 0 { flush::large_integer(lsn_pointer) } else { 0 };
    dirty_bcb(bcb_at(bcb).shared_cache_map.get(), bcb, lsn);
    Ok(())
}

/// CcUnpinData(Bcb): `vacb | 1` solta o mapeamento; um OBCB solta cada BCB
/// do vetor (terminado em NULL) e é liberado; um BCB perde um pin e, limpo e
/// sem pins, é liberado.
pub fn unpin_data(bcb: u64) -> CcResult<()> {
    if bcb & 1 != 0 {
        let (base, index) = vacb::owner_of_vacb(bcb & !1);
        {
            let mut cache = CACHE.lock();
            if let Some(view) = cache.maps.get_mut(&base).and_then(|map| map.views.get_mut(&index)) {
                view.maps = view.maps.saturating_sub(1);
                vacb::publish_active_count(view);
            }
        }
        cache_map::release_view(base, index);
        return Ok(());
    }
    if bcb_at(bcb).node_type_code.get() == layout::NTC_OBCB {
        // SAFETY: o nó é um OBCB (NodeTypeCode 0x2FA).
        let overlap = unsafe { Obcb::at(bcb) };
        let mut index = 0;
        loop {
            let member = overlap.bcb(index).get();
            if member == 0 {
                break;
            }
            unpin_data(member)?;
            index += 1;
        }
        guest::free_bytes(bcb);
        return Ok(());
    }
    let base = bcb_at(bcb).shared_cache_map.get();
    let index = {
        let mut cache = CACHE.lock();
        let Some(map) = cache.maps.get_mut(&base) else { return Err(Failure::Kernel(KernelError::new("CcUnpinData on a BCB without cache map"))) };
        let Some(state) = map.bcbs.get_mut(&bcb) else { return Err(Failure::Kernel(KernelError::new("CcUnpinData on an unknown BCB"))) };
        state.pins = state.pins.saturating_sub(1);
        bcb_at(bcb).pin_count.atomic().store(state.pins, Ordering::SeqCst);
        let index = state.view;
        if state.pins == 0 && !state.dirty {
            map.bcbs.remove(&bcb);
            cache_map::free_native_bcb(bcb);
        }
        index
    };
    cache_map::release_view(base, index);
    Ok(())
}

/// CcRepinBcb(Bcb): mais um pin (segurado até CcUnpinRepinnedBcb).
pub fn repin_bcb(bcb: u64) -> CcResult<()> {
    if !is_bcb(bcb) {
        crate::ntos::ke::bugcheck::raise_bug_check(0x34, 0x2073, 0xFFFF_FFFF_C000_0420, 0, 0);
    }
    let base = bcb_at(bcb).shared_cache_map.get();
    let mut cache = CACHE.lock();
    let Some(map) = cache.maps.get_mut(&base) else { return Ok(()) };
    let Some(state) = map.bcbs.get_mut(&bcb) else { return Ok(()) };
    state.pins += 1;
    bcb_at(bcb).pin_count.atomic().store(state.pins, Ordering::SeqCst);
    let index = state.view;
    if let Some(view) = map.views.get_mut(&index) {
        view.refs += 1;
    }
    Ok(())
}

/// CcUnpinRepinnedBcb(Bcb, WriteThrough, IoStatus): com WriteThrough e BCB
/// sujo, grava o intervalo e devolve o status do flush; depois solta o pin.
pub fn unpin_repinned_bcb(bcb: u64, write_through: bool, io_status: u64) -> CcResult<()> {
    let mut result = (layout::status::SUCCESS, 0u64);
    if write_through && bcb & 1 == 0 {
        let base = bcb_at(bcb).shared_cache_map.get();
        let range = CACHE.lock().maps.get(&base).and_then(|map| map.bcbs.get(&bcb)).filter(|state| state.dirty).map(|state| (state.offset, state.offset + state.length as u64));
        if let Some((start, end)) = range {
            result = flush::write_range(base, start & !(PAGE_SIZE - 1), end, None)?;
        }
    }
    if io_status != 0 {
        // SAFETY: PIO_STATUS_BLOCK de kernel do file system.
        let block = unsafe { IoStatusBlock::at(io_status) };
        block.status.set(result.0 as i32);
        block.information.set(result.1);
    }
    unpin_data(bcb)
}

/// CcRemapBcb(Bcb): mais um mapeamento da vista do BCB; devolve `vacb | 1`.
pub fn remap_bcb(bcb: u64) -> CcResult<u64> {
    let untagged = bcb & !1;
    let vacb = if bcb & 1 != 0 {
        untagged
    } else if bcb_at(untagged).node_type_code.get() == layout::NTC_OBCB {
        // SAFETY: o nó é um OBCB; o primeiro membro é um BCB vivo.
        bcb_at(unsafe { Obcb::at(untagged) }.bcb(0).get()).vacb.get()
    } else {
        bcb_at(untagged).vacb.get()
    };
    let (base, index) = vacb::owner_of_vacb(vacb);
    let mut cache = CACHE.lock();
    if let Some(view) = cache.maps.get_mut(&base).and_then(|map| map.views.get_mut(&index)) {
        view.maps += 1;
        view.refs += 1;
        vacb::publish_active_count(view);
    }
    Ok(vacb | 1)
}

/// CcGetFileObjectFromBcb: `Bcb->SharedCacheMap->FileObjectFastRef & ~0xF`.
pub fn file_object_from_bcb(bcb: u64) -> u64 {
    cache_map::native_map(bcb_at(bcb).shared_cache_map.get()).file_object_fast_ref.object.get() & !0xF
}
