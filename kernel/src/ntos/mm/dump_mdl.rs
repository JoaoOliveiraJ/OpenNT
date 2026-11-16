//! Janela de mapeamento do dump legado.
//!
//! Uma janela pré-reservada de 32 PTEs de sistema. Os chamadores serializam
//! seu uso; o próximo mapeamento substitui a vista do MDL anterior. Mapear
//! nunca aloca frames nem tabelas.

use core::sync::atomic::{AtomicBool, Ordering};

use super::paging::{self, MapOptions};
use super::{memory_map as map, physical_layout};
use crate::rtl::KernelError;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::Mdl;

const BASE: u64 = map::KERNEL_DUMP_VIRTUAL_BASE;
const PAGES: u64 = 32;
static READY: AtomicBool = AtomicBool::new(false);
static BUSY: AtomicBool = AtomicBool::new(false);

fn reserve(page: u64) -> bool {
    paging::map_page(BASE + page * 4096, 0, 0x200, MapOptions { nx: true, ..Default::default() })
}

/// Entradas não presentes possuídas retêm a hierarquia pré-alocada.
pub fn init() -> Result<(), KernelError> {
    if READY.load(Ordering::Acquire) {
        return Ok(());
    }
    for count in 0..PAGES {
        if !reserve(count) {
            for page in 0..count {
                paging::unmap_page(BASE + page * 4096, MapOptions::default());
            }
            return Err(KernelError::new("dump window page tables exhausted"));
        }
    }
    READY.store(true, Ordering::Release);
    Ok(())
}

/// A seleção PAT do alias primário: misturar tipos de cache é inválido.
fn cache_flags(physical: u64) -> u64 {
    match paging::query_page(physical, false) {
        Some(page) if page.physical_address == physical => (page.flags & 0x18) | if page.pat { 0x80 } else { 0 },
        _ => 0,
    }
}

pub fn map(mdl: u64) -> Result<(), KernelError> {
    if !READY.load(Ordering::Acquire) {
        return Err(KernelError::new("dump window is not initialized"));
    }
    if BUSY.swap(true, Ordering::AcqRel) {
        return Err(KernelError::new("dump mapping reentrancy"));
    }
    let result = (|| {
        // SAFETY: o PMDL do driver de dump; as leituras continuam sondadas.
        let descriptor = unsafe { Mdl::at(mdl) };
        let bytes = descriptor.byte_count.probe_get()? as u64;
        let offset = descriptor.byte_offset.probe_get()? as u64;
        let count = (bytes + offset).div_ceil(4096);
        if bytes == 0 || offset >= 4096 || count > PAGES {
            return Err(KernelError::new("invalid MDL for the 32-page dump window"));
        }
        let admitted = physical_layout::ranges();
        let mut frames = alloc::vec::Vec::new();
        for index in 0..count {
            // O vetor de PFNs logo depois do cabeçalho.
            // SAFETY: entrada do vetor dimensionado pelo MDL (lida com sonda).
            let entry = unsafe { Field::<u64>::at(mdl + Mdl::SIZE + index * 8) };
            let frame = entry.probe_get()?.wrapping_mul(4096);
            if !admitted.iter().any(|&(base, top)| frame >= base && frame + 4096 <= top) {
                return Err(KernelError::new("dump MDL references a PFN outside admitted RAM"));
            }
            frames.push((frame, cache_flags(frame)));
        }
        // Valida o MDL inteiro antes de substituir qualquer parte da vista.
        for index in 0..count {
            if !reserve(index) {
                return Err(KernelError::new("reserved dump PTE disappeared"));
            }
        }
        descriptor.mapped_system_va.probe_set(BASE + offset)?;
        for (index, &(frame, cache)) in frames.iter().enumerate() {
            if !paging::map_page(BASE + index as u64 * 4096, frame, 0x63 | cache, MapOptions { nx: true, ..Default::default() }) {
                return Err(KernelError::new("reserved dump mapping failed"));
            }
        }
        // MDL_MAPPED_TO_SYSTEM_VA | MDL_PARTIAL.
        descriptor.mdl_flags.probe_set(descriptor.mdl_flags.probe_get()? | 0x11)
    })();
    BUSY.store(false, Ordering::Release);
    result
}

// ---- MmMapMemoryDumpMdlEx (ntoskrnl 19041 rva 0x383670) ------------------------
//
// MmMapMemoryDumpMdlEx(Va, PageTotal, MemoryDumpMdl, Flags): Flags só aceita
// MM_DUMP_MAP_INVALIDATE (2); qualquer outro bit é STATUS_INVALID_PARAMETER_4.
// O MiMapMemoryDumpMdl zera os PTEs das páginas que o MDL abrange a partir
// de Va (ADDRESS_AND_SIZE_TO_SPAN_PAGES de ByteOffset/ByteCount; PageTotal
// não é usado), grava MappedSystemVa = Va + ByteOffset e então: com
// INVALIDATE só desliga MDL_MAPPED_TO_SYSTEM_VA e
// MDL_PARTIAL_HAS_BEEN_MAPPED; sem ela mapeia cada PFN leitura e escrita
// com o atributo de cache compatível com o do frame e liga
// MDL_MAPPED_TO_SYSTEM_VA | MDL_PARTIAL. O Va vem do chamador (uma faixa de
// MmAllocateMappingAddress, como a do pmem.sys); no OpenNT ele tem de ser
// uma reserva dessas ou a janela do dump, e o MDL só pode citar RAM.

const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const DUMP_MAP_INVALIDATE: u32 = 2;

/// Onde fica a faixa [Va, Va + páginas): a janela do dump (índice da
/// primeira página) ou uma reserva de MmAllocateMappingAddress.
#[derive(Clone, Copy)]
enum Window {
    Dump(u64),
    Reserved,
}

fn window_of(va: u64, count: u64) -> Option<Window> {
    let bytes = count.checked_mul(4096)?;
    if va % 4096 != 0 {
        return None;
    }
    if va >= BASE && va.checked_add(bytes)? <= BASE + PAGES * 4096 {
        return Some(Window::Dump((va - BASE) / 4096));
    }
    super::mdl::reserved_mapping_covers(va, bytes).then_some(Window::Reserved)
}

/// O PTE da página `index` da faixa volta a não presente.
fn clear_page(window: Window, va: u64, index: u64) -> bool {
    match window {
        Window::Dump(first) => reserve(first + index),
        Window::Reserved => {
            paging::unmap_page(va + index * 4096, MapOptions::default());
            true
        }
    }
}

/// MmMapMemoryDumpMdlEx: devolve o NTSTATUS.
pub fn map_at(va: u64, mdl: u64, flags: u32) -> Result<u32, KernelError> {
    if flags & !DUMP_MAP_INVALIDATE != 0 {
        return Ok(STATUS_INVALID_PARAMETER_4);
    }
    // SAFETY: o PMDL do driver de dump; as leituras continuam sondadas.
    let descriptor = unsafe { Mdl::at(mdl) };
    let bytes = descriptor.byte_count.probe_get()?;
    let offset = descriptor.byte_offset.probe_get()?;
    let sum = bytes.wrapping_add(offset);
    let count = ((sum >> 12) + u32::from(sum & 0xFFF != 0)) as u64;
    let Some(window) = window_of(va, count) else {
        return Err(KernelError::new("MmMapMemoryDumpMdlEx: Va fora de uma faixa reservada"));
    };
    let mut frames = alloc::vec::Vec::new();
    if flags & DUMP_MAP_INVALIDATE == 0 {
        let admitted = physical_layout::ranges();
        for index in 0..count {
            // SAFETY: entrada do vetor dimensionado pelo MDL (lida com sonda).
            let entry = unsafe { Field::<u64>::at(mdl + Mdl::SIZE + index * 8) };
            let frame = entry.probe_get()?.wrapping_mul(4096);
            if !admitted.iter().any(|&(base, top)| frame >= base && frame + 4096 <= top) {
                return Err(KernelError::new("dump MDL references a PFN outside admitted RAM"));
            }
            frames.push((frame, cache_flags(frame)));
        }
    }
    if matches!(window, Window::Dump(_)) && BUSY.swap(true, Ordering::AcqRel) {
        return Err(KernelError::new("dump mapping reentrancy"));
    }
    let result = (|| {
        for index in 0..count {
            if !clear_page(window, va, index) {
                return Err(KernelError::new("reserved dump PTE disappeared"));
            }
        }
        descriptor.mapped_system_va.probe_set(va + offset as u64)?;
        if flags & DUMP_MAP_INVALIDATE != 0 {
            // MDL_MAPPED_TO_SYSTEM_VA | MDL_PARTIAL_HAS_BEEN_MAPPED.
            return descriptor.mdl_flags.probe_set(descriptor.mdl_flags.probe_get()? & !0x21);
        }
        for (index, &(frame, cache)) in frames.iter().enumerate() {
            if !paging::map_page(va + index as u64 * 4096, frame, 0x63 | cache, MapOptions { nx: true, ..Default::default() }) {
                return Err(KernelError::new("dump mapping failed"));
            }
        }
        // MDL_MAPPED_TO_SYSTEM_VA | MDL_PARTIAL.
        descriptor.mdl_flags.probe_set(descriptor.mdl_flags.probe_get()? | 0x11)
    })();
    if matches!(window, Window::Dump(_)) {
        BUSY.store(false, Ordering::Release);
    }
    result.map(|()| 0)
}

/// Desmontagem interna (testes/desligamento), não um export.
pub fn clear() -> Result<(), KernelError> {
    if !READY.load(Ordering::Acquire) {
        return Ok(());
    }
    if BUSY.load(Ordering::Acquire) {
        return Err(KernelError::new("dump mapping is active"));
    }
    for page in 0..PAGES {
        if !reserve(page) {
            return Err(KernelError::new("reserved dump PTE disappeared"));
        }
    }
    Ok(())
}
