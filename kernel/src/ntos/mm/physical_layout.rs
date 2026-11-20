//! RAM admitida por este boot: o MmPhysicalMemoryBlock.
//!
//! Como no 19041 (o MmInitializeMemoryLimits sobre a lista de descritores de
//! memória do carregador), o bloco de memória física é toda a RAM que o
//! firmware entrega, abaixo do limite do mapa direto do stage2: os
//! descritores de RAM do E820 menos os reservados, ACPI e NVS, em páginas
//! inteiras. A página física 0 fica de fora, como a página do firmware que
//! o carregador do Windows reserva (num 19041 o primeiro trecho do bloco
//! começa no PFN 1). A memória que o kernel já ocupa no boot (a imagem, a
//! pilha de boot, o heap, as tabelas abaixo de 1 MB) continua sendo RAM
//! física do bloco, como a memória do carregador no NT; só não entra no
//! alocador de frames (`pfn`).
//!
//! O bloco é a fonte única dos totais que o 19041 tira do
//! MmNumberOfPhysicalPages, do MmLowestPhysicalPage e do
//! MmHighestPhysicalPage (`number_of_physical_pages`, `lowest_physical_page`,
//! `highest_physical_page`): SystemBasicInformation, as classes 182 e 184, a
//! KUSER_SHARED_DATA, o commit inicial e o MmGetPhysicalMemoryRanges. Uma
//! consulta nunca relê o E820 mutável.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::memory_map as map;
use crate::hal::physical;
use crate::rtl::{KernelError, SpinLock};

static ADMITTED: SpinLock<Option<Vec<(u64, u64)>>> = SpinLock::new(None);
/// MmNumberOfPhysicalPages, MmLowestPhysicalPage e MmHighestPhysicalPage do
/// bloco, gravados uma vez no `init`.
static NUMBER_OF_PHYSICAL_PAGES: AtomicU64 = AtomicU64::new(0);
static LOWEST_PHYSICAL_PAGE: AtomicU64 = AtomicU64::new(0);
static HIGHEST_PHYSICAL_PAGE: AtomicU64 = AtomicU64::new(0);
/// A página física 0, que o bloco nunca inclui.
const FIRMWARE_PAGE_TOP: u64 = map::PAGE_SIZE;

/// Uma entrada do mapa de memória do firmware (INT 15h E820), como a BIOS a
/// entregou: base, tamanho e tipo (1 = RAM, 2 = reservada, 3 = ACPI, 4 = NVS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareRange {
    pub base: u64,
    pub length: u64,
    pub range_type: u32,
}

/// O mapa E820 habilitado (bit 0 dos atributos estendidos), copiado no boot.
static FIRMWARE_MAP: SpinLock<Vec<FirmwareRange>> = SpinLock::new(Vec::new());

pub fn init() -> Result<(), KernelError> {
    let count = physical::read16(map::E820_COUNT_PHYS) as u64;
    if count == 0 || count > map::E820_MAX_ENTRIES {
        return Err(KernelError::new("Invalid E820 table for physical memory initialization"));
    }
    let mut usable = Vec::new();
    let mut reserved = Vec::new();
    let mut firmware = Vec::new();
    for index in 0..count {
        let at = map::E820_TABLE_PHYS + index * 24;
        if physical::read32(at + 20) & 1 == 0 {
            continue;
        }
        firmware.push(FirmwareRange { base: physical::read64(at), length: physical::read64(at + 8), range_type: physical::read32(at + 16) });
        let base = physical::read64(at);
        let length = physical::read64(at + 8);
        let end = base.saturating_add(length);
        if length == 0 || base >= map::PHYSICAL_MEMORY_LIMIT {
            continue;
        }
        let range = (base, end.min(map::PHYSICAL_MEMORY_LIMIT));
        if physical::read32(at + 16) == 1 { usable.push(range) } else { reserved.push(range) }
    }
    let mut candidates = usable;
    for &(low, high) in &reserved {
        let mut remaining = Vec::new();
        for &(base, top) in &candidates {
            if high <= base || low >= top {
                remaining.push((base, top));
            } else {
                if base < low {
                    remaining.push((base, low));
                }
                if top > high {
                    remaining.push((high, top));
                }
            }
        }
        candidates = remaining;
    }
    // União antes do alinhamento: descritores parciais adjacentes podem
    // cobrir juntos um frame inteiro. Bytes reservados excluem o frame tocado.
    candidates.sort();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (base, top) in candidates {
        match merged.last_mut() {
            Some(last) if base <= last.1 => last.1 = last.1.max(top),
            _ => merged.push((base, top)),
        }
    }
    let page = map::PAGE_SIZE;
    let admitted: Vec<(u64, u64)> = merged
        .into_iter()
        .map(|(base, top)| (base.max(FIRMWARE_PAGE_TOP).div_ceil(page) * page, top / page * page))
        .filter(|(base, top)| base < top)
        .collect();
    let (Some(&(lowest, _)), Some(&(_, highest))) = (admitted.first(), admitted.last()) else {
        return Err(KernelError::new("E820 without usable RAM"));
    };
    NUMBER_OF_PHYSICAL_PAGES.store(admitted.iter().map(|&(base, top)| (top - base) / page).sum(), Ordering::Release);
    LOWEST_PHYSICAL_PAGE.store(lowest / page, Ordering::Release);
    HIGHEST_PHYSICAL_PAGE.store(highest / page - 1, Ordering::Release);
    *ADMITTED.lock() = Some(admitted);
    *FIRMWARE_MAP.lock() = firmware;
    Ok(())
}

/// MmNumberOfPhysicalPages: as páginas do bloco de memória física (0 antes
/// do init).
pub fn number_of_physical_pages() -> u64 {
    NUMBER_OF_PHYSICAL_PAGES.load(Ordering::Acquire)
}

/// MmLowestPhysicalPage: o primeiro PFN do bloco.
pub fn lowest_physical_page() -> u64 {
    LOWEST_PHYSICAL_PAGE.load(Ordering::Acquire)
}

/// MmHighestPhysicalPage: o último PFN do bloco.
pub fn highest_physical_page() -> u64 {
    HIGHEST_PHYSICAL_PAGE.load(Ordering::Acquire)
}

/// O mapa de memória do firmware, na ordem da BIOS.
pub fn firmware_map() -> Vec<FirmwareRange> {
    FIRMWARE_MAP.lock().clone()
}

pub fn ranges() -> Vec<(u64, u64)> {
    ADMITTED.lock().clone().expect("Physical memory layout is not initialized")
}

/// Só autoriza cópias em bloco sobre RAM admitida pelo E820.
pub fn contains_ram_range(physical_address: u64, byte_count: u64) -> bool {
    let admitted = ADMITTED.lock();
    let Some(ranges) = admitted.as_ref() else { return false };
    if byte_count == 0 {
        return false;
    }
    let Some(end) = physical_address.checked_add(byte_count) else { return false };
    ranges.iter().any(|&(base, top)| physical_address >= base && end <= top)
}

// ---- Mm64BitPhysicalAddress (mm-physical-memory) ----------------------------
//
// BOOLEAN exportado: no x64 o MiMemoryLicense grava 1 incondicionalmente. A
// célula é a entrada "Mm64BitPhysicalAddress" de `kernel_data_layout` (valor
// inicial 1); o PE do kernel e a tabela de exports publicam os mesmos bytes.

/// Endereço da célula Mm64BitPhysicalAddress (export de dados).
pub fn sixty_four_bit_physical_address_cell() -> u64 {
    super::kernel_data::required_address("Mm64BitPhysicalAddress")
}

// ---- MmAddPhysicalMemory (ntoskrnl 19041 0x8c6290) ---------------------------
//
// MmAddPhysicalMemory(StartAddress*, NumberOfBytes*): um StartAddress fora
// de página com o bit 0 ligado perde o bit (o pedido de memória espelhada);
// MiAddPhysicalMemoryChunks anda a faixa em páginas inteiras (NumberOfBytes
// truncado) e MiAddPhysicalMemory recusa um início fora de página ou uma
// faixa vazia (STATUS_INVALID_PARAMETER_1), corta o fim no maior PFN
// possível (o MAXPHYADDR da CPU, no máximo 0xFFFFFFFFF), trata as páginas
// do topo (>= 0xFFFFFFFFA) e as já presentes como STATUS_CONFLICTING_ADDRESSES
// e, para memória nova, cria as entradas do banco de PFN e a entrega ao
// alocador. *NumberOfBytes recebe o que foi acrescentado. O banco de PFN do
// OpenNT é montado uma vez no boot sobre o mapa direto e não cresce: a
// memória nova recebe STATUS_INSUFFICIENT_RESOURCES, o status do original
// quando as entradas novas não podem ser mapeadas.

const ADD_STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
const ADD_STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const ADD_STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;

/// MmAddPhysicalMemory: (NTSTATUS, bytes acrescentados).
pub fn add_physical_memory(start: u64, bytes: u64) -> (u32, u64) {
    let start = if start & 0xFFF != 0 && start & 1 != 0 { start & !1 } else { start };
    if start & 0xFFF != 0 {
        return (ADD_STATUS_INVALID_PARAMETER_1, 0);
    }
    let first = start >> 12;
    let width = crate::hal::cpu::cpuid(0x8000_0008)[0] & 0xFF;
    let highest = if (12..64).contains(&width) { ((1u64 << width) >> 12) - 1 } else { 0xF_FFFF_FFFF }.min(0xF_FFFF_FFFF);
    let end = first.saturating_add(bytes >> 12).min(highest + 1);
    if first >= end {
        return (ADD_STATUS_INVALID_PARAMETER_1, 0);
    }
    if end >= 0xF_FFFF_FFFA {
        return (ADD_STATUS_CONFLICTING_ADDRESSES, 0);
    }
    let (low, high) = (first << 12, end << 12);
    if ranges().iter().any(|&(base, top)| low < top && high > base) {
        return (ADD_STATUS_CONFLICTING_ADDRESSES, 0);
    }
    (ADD_STATUS_INSUFFICIENT_RESOURCES, 0)
}

// ---- MmRemovePhysicalMemory (ntoskrnl 19041 0x8c62e0) ------------------------
//
// MmRemovePhysicalMemory(StartAddress*, NumberOfBytes*): o número de páginas
// é NumberOfBytes >> 12; um StartAddress fora de página com o bit 0 ligado é
// o pedido de remover páginas ruins (o bit sai). Faixa vazia ou que dá a
// volta é STATUS_INVALID_PARAMETER_1. As páginas ruins saem da lista de
// páginas ruins (MiRemoveBadPages), que só existe com o rastreamento de
// páginas ruins do MiFlags ligado; sem ele é STATUS_NOT_IMPLEMENTED. Para
// RAM comum, o MiFindContiguousPages tem de tomar todas as páginas da
// faixa antes de o MiRemovePhysicalMemory tirá-las do bloco de memória
// física; quando não consegue, o status dele volta e nada muda
// (STATUS_NO_MEMORY). O OpenNT não tem remoção a quente: o bloco de memória
// física e o banco de PFN são fixos depois do boot, o rastreamento de
// páginas ruins fica desligado e nenhuma faixa pode ser tomada, então todo
// pedido válido termina nesses dois status, como num Windows sem memória
// removível. *NumberOfBytes só muda num sucesso.

const REMOVE_STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const REMOVE_STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const REMOVE_STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// MmRemovePhysicalMemory: o NTSTATUS (o OpenNT nunca remove páginas).
pub fn remove_physical_memory(start: u64, bytes: u64) -> u32 {
    let pages = bytes >> 12;
    let bad_pages = start & 0xFFF != 0 && start & 1 != 0;
    let start = if bad_pages { start & !1 } else { start };
    let first = start >> 12;
    if first.checked_add(pages).is_none_or(|end| end <= first) {
        return REMOVE_STATUS_INVALID_PARAMETER_1;
    }
    if bad_pages {
        return REMOVE_STATUS_NOT_IMPLEMENTED;
    }
    REMOVE_STATUS_NO_MEMORY
}
