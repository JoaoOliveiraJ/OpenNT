//! Mapeamentos de I/O space do Mm (MmMapIoSpace, MmMapIoSpaceEx,
//! MmUnmapIoSpace). Toda a faixa física já está no mapa direto da metade de
//! sistema: mapear devolve a VA de sistema `DIRECT_MAP_BASE + PA`, e a
//! tabela rastreia os mapeamentos ativos e o unmap, como o NT.

use alloc::collections::BTreeMap;

use crate::hal::physical;
use crate::rtl::SpinLock;

/// Mapeamentos de I/O space ativos: VA -> (PA, tamanho).
static IO_SPACE_MAPPINGS: SpinLock<BTreeMap<u64, (u64, u64)>> = SpinLock::new(BTreeMap::new());

/// VA de sistema da faixa física, ou 0 (NULL) fora do mapa direto.
fn system_address(physical_address: u64, size: u64) -> u64 {
    match physical_address.checked_add(size.max(1)) {
        Some(end) if end <= crate::ntos::mm::memory_map::PHYSICAL_MEMORY_LIMIT => physical::to_virtual(physical_address),
        _ => 0,
    }
}

/// MmMapIoSpace — a VA do mapa direto; 0 fora da faixa física mapeada.
pub fn map(physical_address: u64, size: u64) -> u64 {
    let size = size as u32 as u64;
    let address = system_address(physical_address, size);
    if address != 0 {
        IO_SPACE_MAPPINGS.lock().insert(address, (physical_address, size));
    }
    address
}

/// MmUnmapIoSpace.
pub fn unmap(address: u64) {
    IO_SPACE_MAPPINGS.lock().remove(&address);
}

/// MmMapIoSpaceEx — a VA do mapa direto, sem entrada na tabela.
pub fn map_ex(physical_address: u64, size: u64) -> u64 {
    system_address(physical_address, size)
}
