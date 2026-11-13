//! Mapeamentos de I/O space do Mm (MmMapIoSpace, MmMapIoSpaceEx,
//! MmUnmapIoSpace). O mapa do kernel é identidade (VA == PA): mapear devolve
//! o próprio endereço físico, e a tabela rastreia os mapeamentos ativos e o
//! unmap, como o NT.

use alloc::collections::BTreeMap;

use crate::rtl::SpinLock;

/// Mapeamentos de I/O space ativos: VA -> (PA, tamanho).
static IO_SPACE_MAPPINGS: SpinLock<BTreeMap<u64, (u64, u64)>> = SpinLock::new(BTreeMap::new());

/// MmMapIoSpace — identidade: a VA devolvida é o endereço físico.
pub fn map(physical_address: u64, size: u64) -> u64 {
    IO_SPACE_MAPPINGS.lock().insert(physical_address, (physical_address, size as u32 as u64));
    physical_address
}

/// MmUnmapIoSpace.
pub fn unmap(address: u64) {
    IO_SPACE_MAPPINGS.lock().remove(&address);
}

/// MmMapIoSpaceEx — identidade, sem entrada na tabela.
pub fn map_ex(physical_address: u64) -> u64 {
    physical_address
}
