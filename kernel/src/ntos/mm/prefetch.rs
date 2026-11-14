//! Pré-busca de memória virtual: MmPrefetchVirtualAddresses (ntoskrnl
//! 19041).
//!
//! O pedido (Version, Flags, Process, NumberOfEntries, VirtualAddresses: um
//! vetor de MEMORY_RANGE_ENTRY {VirtualAddress, NumberOfBytes}) é conferido
//! como no NT — Version diferente de 1, Flags fora dos três bits ou com os
//! bits 1 e 2 juntos dão STATUS_INVALID_PARAMETER_1 — e cada faixa é
//! trazida para a memória no espaço do processo (anexado a ele): cada
//! página de usuário da faixa é lida uma vez, o que resolve as faltas de
//! demanda das páginas comprometidas. A pré-busca é um conselho: página
//! inacessível não é erro, e o resultado é STATUS_SUCCESS.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map;
use crate::ntos::ps::process_context;
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const PAGE: u64 = 0x1000;

/// O pedido de pré-busca.
#[repr(C)]
pub struct PrefetchRequest {
    pub version: Field<u32>,
    pub flags: Field<u32>,
    pub process: Field<u64>,
    pub number_of_entries: Field<u64>,
    pub virtual_addresses: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PrefetchRequest {}

/// MEMORY_RANGE_ENTRY.
#[repr(C)]
struct MemoryRangeEntry {
    virtual_address: Field<u64>,
    number_of_bytes: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for MemoryRangeEntry {}

/// Páginas que uma faixa pede, no máximo (o resto é ignorado: conselho).
const MAXIMUM_PAGES_PER_RANGE: u64 = 0x1_0000;

/// MmPrefetchVirtualAddresses(Request). Devolve o NTSTATUS e as páginas
/// lidas.
pub fn prefetch_virtual_addresses(request: &PrefetchRequest) -> Result<(u32, u64), KernelError> {
    let flags = request.flags.get();
    if request.version.get() != 1 || flags >= 8 || flags & 6 == 6 {
        return Ok((STATUS_INVALID_PARAMETER_1, 0));
    }
    let (process, count, entries) = (request.process.get(), request.number_of_entries.get(), request.virtual_addresses.get());
    process_context::with_process(process, || {
        let mut touched = 0;
        for index in 0..count {
            // SAFETY: o vetor de faixas do chamador de kernel.
            let entry = unsafe { MemoryRangeEntry::at(entries + index * MemoryRangeEntry::SIZE) };
            let (start, length) = (entry.virtual_address.get(), entry.number_of_bytes.get());
            let Some(end) = start.checked_add(length) else { continue };
            let mut page = start & !(PAGE - 1);
            let mut pages = 0;
            while page < end && page < memory_map::USER_PROBE_ADDRESS && pages < MAXIMUM_PAGES_PER_RANGE {
                if guest::try_read::<u8>(page).is_ok() {
                    touched += 1;
                }
                page += PAGE;
                pages += 1;
            }
        }
        Ok((0, touched))
    })?
}
