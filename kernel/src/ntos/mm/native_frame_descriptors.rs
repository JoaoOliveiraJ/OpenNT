//! Descritores físicos no layout MMPFN de 48 bytes do NT.
//!
//! O bitmap do PFN decide a propriedade; estes bytes acompanham suas
//! transições e as referências das tabelas que a CPU realmente usa.
//! Campos usados: u1.Flink, PteAddress, u2 (Blink/ShareCount),
//! u3.ReferenceCount, u3.e1 (PageLocation, CacheAttribute) e u4
//! (PteFrame, PfnExists).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{memory_map as map, pfn::AllocationSnapshot};
use crate::hal::physical;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Mmpfn, Mmpfnentry1, MmpfnU4};
use crate::rtl::{KernelError, SpinLock};

pub const DESCRIPTOR_SIZE: u64 = Mmpfn::SIZE;
const FRAME_NUMBER_MASK: u64 = 0xF_FFFF_FFFF;
const FRAME_EXISTS: u64 = MmpfnU4::PFN_EXISTS_MASK;
const FREE_PAGE: u8 = 1;
const ACTIVE_PAGE: u8 = 6;
const CACHED_MEMORY: u8 = 1;
const LIST_END: u64 = FRAME_NUMBER_MASK;

/// Uma referência de PTE a um frame.
#[derive(Clone, Copy, Debug)]
pub struct Reference {
    pub physical_address: u64,
    pub virtual_address: u64,
    pub table_page: bool,
    pub cache_attribute: u8,
}

struct Descriptors {
    physical_base: u64,
    virtual_base: u64,
    frame_count: u64,
    first_free_frame: u64,
    last_free_frame: u64,
    free_frame_count: u64,
    /// Só frames com aliases adicionais guardam referências fora do descritor.
    additional_references: BTreeMap<u64, BTreeMap<u64, Reference>>,
    primary_table_frames: BTreeSet<u64>,
}

static STATE: SpinLock<Descriptors> = SpinLock::new(Descriptors {
    physical_base: 0,
    virtual_base: 0,
    frame_count: 0,
    first_free_frame: LIST_END,
    last_free_frame: LIST_END,
    free_frame_count: 0,
    additional_references: BTreeMap::new(),
    primary_table_frames: BTreeSet::new(),
});

/// Ponteiros de 64 bits nunca ficam publicados como duas metades: uma
/// escrita atômica (com barreira) do qword inteiro.
fn write_exact(field: &Field<u64>, replacement: u64) {
    field.atomic().store(replacement, Ordering::SeqCst);
}

/// Descritor pelo endereço físico (`physical_base + 48 * frame`).
fn pfn(address: u64) -> &'static Mmpfn {
    // SAFETY: descritor do banco de PFNs, alcançado pela VA do mapa direto,
    // sob o lock STATE.
    unsafe { Mmpfn::at(physical::range_to_virtual(address, DESCRIPTOR_SIZE)) }
}

fn page_location(address: u64) -> u8 {
    pfn(address).u3.e1.page_location()
}

/// PageLocation (bits baixos) | CacheAttribute << 6 (o byte u3.e1).
fn entry_byte(location: u8, cache: u8) -> u8 {
    location | cache << Mmpfnentry1::CACHE_ATTRIBUTE_SHIFT
}

impl Descriptors {
    fn descriptor_address(&self, frame_number: u64) -> u64 {
        if self.physical_base == 0 || frame_number >= self.frame_count {
            return 0;
        }
        self.physical_base + frame_number * DESCRIPTOR_SIZE
    }

    fn existing_address(&self, frame_number: u64) -> u64 {
        let address = self.descriptor_address(frame_number);
        if address != 0 && pfn(address).u4.pfn_exists() != 0 { address } else { 0 }
    }

    /// Os links da lista livre são números de frames (campos de 36 bits).
    fn remove_free_frame(&mut self, address: u64) {
        let entry = pfn(address);
        let next = entry.u1.flink();
        let previous = entry.u2.blink();
        if previous == LIST_END {
            self.first_free_frame = next;
        } else {
            write_exact(&pfn(self.descriptor_address(previous)).u1.next, next);
        }
        if next == LIST_END {
            self.last_free_frame = previous;
        } else {
            write_exact(&pfn(self.descriptor_address(next)).u2.entire_field, previous);
        }
        self.free_frame_count -= 1;
    }

    fn append_free_frame(&mut self, frame_number: u64, address: u64) {
        let entry = pfn(address);
        write_exact(&entry.u1.next, FRAME_NUMBER_MASK);
        write_exact(&entry.u2.entire_field, self.last_free_frame);
        if self.last_free_frame == LIST_END {
            self.first_free_frame = frame_number;
        } else {
            write_exact(&pfn(self.descriptor_address(self.last_free_frame)).u1.next, frame_number);
        }
        self.last_free_frame = frame_number;
        self.free_frame_count += 1;
    }

    fn can_release(&self, physical_address: u64) -> bool {
        let address = self.existing_address(physical_address / 4096);
        address != 0
            && page_location(address) == ACTIVE_PAGE
            && pfn(address).u3.reference_count.get() == 1
            && pfn(address).u2.entire_field.get() == 0
    }

    fn primary_reference(&self, frame_number: u64, address: u64) -> Reference {
        let entry = pfn(address);
        let pointer = entry.pte_address.get();
        let table_frame = entry.u4.pte_frame();
        Reference {
            physical_address: table_frame * 4096 + (pointer & 4095),
            virtual_address: pointer,
            table_page: self.primary_table_frames.contains(&frame_number),
            cache_attribute: entry.u3.e1.cache_attribute(),
        }
    }

    fn publish_primary(&mut self, frame_number: u64, address: u64, reference: &Reference) {
        let entry = pfn(address);
        let flags = entry.u4.entire_field.get() & !FRAME_NUMBER_MASK;
        write_exact(&entry.u4.entire_field, flags | reference.physical_address / 4096);
        let state = entry.u3.e1.bitfield_0.get() & !Mmpfnentry1::CACHE_ATTRIBUTE_MASK;
        entry.u3.e1.bitfield_0.set(state | reference.cache_attribute << Mmpfnentry1::CACHE_ATTRIBUTE_SHIFT);
        write_exact(&entry.pte_address, reference.virtual_address);
        if reference.table_page {
            self.primary_table_frames.insert(frame_number);
        } else {
            self.primary_table_frames.remove(&frame_number);
        }
    }

    fn refresh_reference(&mut self, frame_number: u64, reference: &Reference) {
        let address = self.existing_address(frame_number);
        if address == 0 || page_location(address) != ACTIVE_PAGE || pfn(address).u2.entire_field.get() == 0 {
            return;
        }
        let primary = self.primary_reference(frame_number, address);
        if let Some(references) = self.additional_references.get_mut(&frame_number) {
            if references.contains_key(&reference.physical_address) {
                references.insert(reference.physical_address, *reference);
            }
        }
        if primary.physical_address == reference.physical_address {
            self.publish_primary(frame_number, address, reference);
        }
    }
}

/// Configuração montada por `native_pfn_database`.
pub struct Configuration {
    pub physical_base: u64,
    pub virtual_base: u64,
    pub frame_count: u64,
    pub physical_ranges: Vec<(u64, u64)>,
    pub allocation_ranges: Vec<AllocationSnapshot>,
    pub free_count: u64,
}

/// Antes dos APs. Lacunas de firmware ficam sem PfnExists e nunca entram na
/// lista livre.
pub fn initialize(configuration: Configuration) -> Result<(), KernelError> {
    let mut state = STATE.lock();
    if state.physical_base != 0 {
        return Err(KernelError::new("native frame descriptors already initialized"));
    }
    if configuration.physical_base == 0
        || configuration.physical_base % map::PAGE_SIZE != 0
        || configuration.frame_count == 0
        || configuration.frame_count > map::PHYSICAL_MEMORY_LIMIT / map::PAGE_SIZE
        || configuration.free_count > configuration.frame_count
    {
        return Err(KernelError::new("invalid native frame descriptor configuration"));
    }
    let mut free_frames: Vec<u32> = Vec::with_capacity(configuration.free_count as usize);
    for range in &configuration.allocation_ranges {
        for (index, &used) in range.bitmap.iter().enumerate() {
            if used == 0 {
                free_frames.push((range.base / 4096 + index as u64) as u32);
            }
        }
    }
    if free_frames.len() as u64 != configuration.free_count {
        return Err(KernelError::new("PFN snapshot accounting mismatch"));
    }
    state.physical_base = configuration.physical_base;
    state.virtual_base = configuration.virtual_base;
    state.frame_count = configuration.frame_count;
    state.first_free_frame = free_frames.first().map_or(LIST_END, |&frame| frame as u64);
    state.last_free_frame = free_frames.last().map_or(LIST_END, |&frame| frame as u64);
    state.free_frame_count = free_frames.len() as u64;

    let admitted: Vec<(u64, u64)> =
        configuration.physical_ranges.iter().map(|&(base, top)| (base / map::PAGE_SIZE, top / map::PAGE_SIZE)).collect();
    physical::zero(configuration.physical_base, (configuration.frame_count * DESCRIPTOR_SIZE) as usize);
    let mut free_index = 0usize;
    let mut admitted_index = 0usize;
    for frame_number in 0..configuration.frame_count {
        while admitted_index < admitted.len() && frame_number >= admitted[admitted_index].1 {
            admitted_index += 1;
        }
        if admitted_index == admitted.len() || frame_number < admitted[admitted_index].0 {
            continue;
        }
        let entry = pfn(configuration.physical_base + frame_number * DESCRIPTOR_SIZE);
        let available = free_frames.get(free_index).is_some_and(|&frame| frame as u64 == frame_number);
        entry.u4.entire_field.set(FRAME_EXISTS);
        entry.u3.reference_count.set(if available { 0 } else { 1 });
        entry.u3.e1.bitfield_0.set(entry_byte(if available { FREE_PAGE } else { ACTIVE_PAGE }, CACHED_MEMORY));
        if available {
            let next = free_frames.get(free_index + 1).map_or(LIST_END, |&frame| frame as u64);
            let previous = if free_index > 0 { free_frames[free_index - 1] as u64 } else { LIST_END };
            entry.u1.next.set(next);
            entry.u2.entire_field.set(previous);
            free_index += 1;
        }
    }
    if free_index != free_frames.len() {
        return Err(KernelError::new("free PFN outside admitted memory"));
    }
    Ok(())
}

/// Só no rollback do bootstrap, depois de desligar os observadores.
pub fn reset() {
    let mut state = STATE.lock();
    state.physical_base = 0;
    state.virtual_base = 0;
    state.frame_count = 0;
    state.first_free_frame = LIST_END;
    state.last_free_frame = LIST_END;
    state.free_frame_count = 0;
    state.additional_references.clear();
    state.primary_table_frames.clear();
}

pub fn allocated(physical_address: u64) {
    let mut state = STATE.lock();
    let frame_number = physical_address / 4096;
    let address = state.existing_address(frame_number);
    assert!(address != 0 && page_location(address) == FREE_PAGE, "allocated PFN was not on native free list");
    state.remove_free_frame(address);
    // u1..u3 zerados (os 40 bytes antes de u4).
    physical::zero(address, core::mem::offset_of!(Mmpfn, u4));
    let entry = pfn(address);
    write_exact(&entry.u4.entire_field, FRAME_EXISTS);
    entry.u3.reference_count.set(1);
    entry.u3.e1.bitfield_0.set(entry_byte(ACTIVE_PAGE, CACHED_MEMORY));
}

pub fn can_release(physical_address: u64) -> bool {
    STATE.lock().can_release(physical_address)
}

pub fn released(physical_address: u64) {
    let mut state = STATE.lock();
    let frame_number = physical_address / 4096;
    assert!(state.can_release(physical_address), "native PFN still referenced at release");
    let address = state.existing_address(frame_number);
    physical::zero(address, core::mem::offset_of!(Mmpfn, u4));
    let entry = pfn(address);
    write_exact(&entry.u4.entire_field, FRAME_EXISTS);
    entry.u3.e1.bitfield_0.set(entry_byte(FREE_PAGE, CACHED_MEMORY));
    state.additional_references.remove(&frame_number);
    state.primary_table_frames.remove(&frame_number);
    state.append_free_frame(frame_number, address);
}

/// RAM livre precisa de dono antes de receber uma referência gerenciada.
pub fn can_map_range(physical_address: u64, byte_length: u64) -> bool {
    let state = STATE.lock();
    let mut address = physical_address;
    while address < physical_address + byte_length {
        let descriptor = state.existing_address(address / 4096);
        if descriptor != 0 && page_location(descriptor) == FREE_PAGE {
            return false;
        }
        address += 4096;
    }
    true
}

/// ShareCount conta PTEs reais; a identidade do boot, o mapa direto e a
/// janela do heap não são donos.
pub fn add_reference(frame_number: u64, reference: Reference) {
    let mut state = STATE.lock();
    let address = state.existing_address(frame_number);
    if address == 0 {
        return;
    }
    assert!(page_location(address) == ACTIVE_PAGE, "mapping unowned RAM frame");
    let count = pfn(address).u2.entire_field.get();
    if count == 0 {
        state.publish_primary(frame_number, address, &reference);
    } else {
        let primary = state.primary_reference(frame_number, address);
        if primary.physical_address == reference.physical_address {
            state.refresh_reference(frame_number, &reference);
            return;
        }
        let references = state
            .additional_references
            .entry(frame_number)
            .or_insert_with(|| BTreeMap::from([(primary.physical_address, primary)]));
        if references.contains_key(&reference.physical_address) {
            state.refresh_reference(frame_number, &reference);
            return;
        }
        references.insert(reference.physical_address, reference);
        if reference.table_page && !primary.table_page {
            state.publish_primary(frame_number, address, &reference);
        }
    }
    write_exact(&pfn(address).u2.entire_field, count + 1);
}

pub fn remove_reference(frame_number: u64, entry_physical_address: u64) {
    let mut state = STATE.lock();
    let address = state.existing_address(frame_number);
    if address == 0 {
        return;
    }
    let entry = pfn(address);
    let count = entry.u2.entire_field.get();
    let primary = state.primary_reference(frame_number, address);
    assert!(count != 0, "removing absent native PFN reference");
    if count == 1 {
        assert!(primary.physical_address == entry_physical_address, "PFN reference mismatch");
        write_exact(&entry.pte_address, 0);
        write_exact(&entry.u4.entire_field, entry.u4.entire_field.get() & !FRAME_NUMBER_MASK);
        state.primary_table_frames.remove(&frame_number);
    } else {
        let references = state.additional_references.get_mut(&frame_number).expect("PFN alias missing");
        assert!(references.remove(&entry_physical_address).is_some(), "PFN alias missing");
        let replacement = if primary.physical_address == entry_physical_address {
            references.values().find(|item| item.table_page).or_else(|| references.values().next()).copied()
        } else {
            None
        };
        let last = references.len() == 1;
        if let Some(replacement) = replacement {
            state.publish_primary(frame_number, address, &replacement);
        }
        if last {
            state.additional_references.remove(&frame_number);
        }
    }
    write_exact(&entry.u2.entire_field, count - 1);
}

/// Trocar o caminho até uma tabela compartilhada muda seu alias recursivo,
/// sem criar outra referência às mesmas células físicas.
pub fn refresh_reference(frame_number: u64, reference: Reference) {
    STATE.lock().refresh_reference(frame_number, &reference);
}

#[derive(Clone, Copy, Debug)]
pub struct Information {
    pub physical_base: u64,
    pub virtual_base: u64,
    pub frame_count: u64,
    pub descriptor_size: u64,
    pub free_count: u64,
    pub first_free_frame: u64,
    pub last_free_frame: u64,
}

pub fn information() -> Option<Information> {
    let state = STATE.lock();
    (state.physical_base != 0).then(|| Information {
        physical_base: state.physical_base,
        virtual_base: state.virtual_base,
        frame_count: state.frame_count,
        descriptor_size: DESCRIPTOR_SIZE,
        free_count: state.free_frame_count,
        first_free_frame: state.first_free_frame,
        last_free_frame: state.last_free_frame,
    })
}
