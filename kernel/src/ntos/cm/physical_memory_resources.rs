//! RAM no mapa de recursos — `system32/ntos/cm/physical-memory-resources.js`.
//!
//! Publica a RAM admitida pelo Memory Manager na hive volátil de hardware. A
//! fonte é a mesma de MmGetPhysicalMemoryRanges: inclui RAM já ocupada pelo
//! kernel e exclui os buracos de firmware/MMIO.

use alloc::vec::Vec;

use super::registry;
use crate::ntos::mm::physical_layout;
use crate::rtl::KernelError;
use crate::ntos::inc::nt_abi::{cm_full_resource_descriptor, cm_partial_resource_descriptor, cm_partial_resource_list, cm_resource_list};

pub const PHYSICAL_MEMORY_KEY: &str = "\\Registry\\Machine\\Hardware\\ResourceMap\\System Resources\\Physical Memory";
const REG_RESOURCE_LIST: u32 = 8;
const FULL_DESCRIPTOR: usize = cm_resource_list::FULL_DESCRIPTOR as usize;
const PARTIAL_LIST: usize = FULL_DESCRIPTOR + cm_full_resource_descriptor::PARTIAL_LIST as usize;
const DESCRIPTORS: usize = PARTIAL_LIST + cm_partial_resource_list::DESCRIPTORS as usize;
const DESCRIPTOR_BYTES: usize = cm_partial_resource_descriptor::SIZE as usize;

/// O layout WDK x64 usa pack(4): a união começa em +4 e ocupa 16 bytes.
const MEMORY_START: usize = 4;
const MEMORY_LENGTH: usize = 12;

/// (tipo, flags, escala, comprimento máximo): Memory e MemoryLarge 40/48/64.
const ENCODINGS: [(u8, u16, u32, u128); 4] = [
    (3, 0, 0, 0xFFFF_FFFF),
    (7, 0x200, 8, 0xFF_FFFF_FF00),
    (7, 0x400, 16, 0xFFFF_FFFF_0000),
    (7, 0x800, 32, 0xFFFF_FFFF_0000_0000),
];

/// Lista contígua sem truncar endereços nem arredondar RAM para dentro de
/// região reservada; toda validação precede a publicação. Os fins são
/// exclusivos (até 2^64).
pub fn encode_ranges(ranges: &[(u128, u128)]) -> Result<Vec<u8>, KernelError> {
    let mut bytes = alloc::vec![0u8; DESCRIPTORS + ranges.len() * DESCRIPTOR_BYTES];
    bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
    // InterfaceType Internal, BusNumber 0; Version e Revision ficam zero.
    bytes[PARTIAL_LIST + 4..PARTIAL_LIST + 8].copy_from_slice(&(ranges.len() as u32).to_le_bytes());
    let mut previous_end = 0u128;
    for (index, &(start, end)) in ranges.iter().enumerate() {
        let length = end.wrapping_sub(start);
        let encoding = ENCODINGS.iter().find(|&&(_, _, shift, maximum)| end > start && length <= maximum && length & ((1u128 << shift) - 1) == 0);
        let valid = start >= previous_end && end > start && end <= 1u128 << 64 && start & 0xFFF == 0 && length & 0xFFF == 0;
        let (Some(&(resource_type, flags, shift, _)), true) = (encoding, valid) else {
            return Err(KernelError::new("Physical memory resource range cannot be represented exactly"));
        };
        let offset = DESCRIPTORS + index * DESCRIPTOR_BYTES;
        bytes[offset] = resource_type;
        bytes[offset + 1] = 1; // CmResourceShareDeviceExclusive
        bytes[offset + 2..offset + 4].copy_from_slice(&flags.to_le_bytes());
        bytes[offset + MEMORY_START..offset + MEMORY_START + 8].copy_from_slice(&(start as u64).to_le_bytes());
        bytes[offset + MEMORY_LENGTH..offset + MEMORY_LENGTH + 4].copy_from_slice(&((length >> shift) as u32).to_le_bytes());
        previous_end = end;
    }
    Ok(bytes)
}

/// Publicado antes dos drivers, depois da inicialização do PFN.
pub fn initialize() -> Result<(), KernelError> {
    let ranges: Vec<(u128, u128)> = physical_layout::ranges().into_iter().map(|(start, end)| (start as u128, end as u128)).collect();
    let bytes = encode_ranges(&ranges)?;
    let handle = registry::open_or_create(PHYSICAL_MEMORY_KEY, None)?;
    if handle == 0 {
        return Err(KernelError::new("Cannot create physical memory resource key"));
    }
    let published = registry::set_value(handle, ".Translated", REG_RESOURCE_LIST, bytes);
    registry::close_handle(handle);
    if !published {
        return Err(KernelError::new("Cannot publish physical memory resource list"));
    }
    Ok(())
}
