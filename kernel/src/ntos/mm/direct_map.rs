//! O mapa direto acima de 4 GB.
//!
//! O stage2 monta o mapa direto de [0, 4 GB) (`memory_map::BOOT_DIRECT_MAP_LIMIT`,
//! uma PDPT e quatro PDs fixas abaixo de 1 MB). A RAM que o firmware entrega
//! acima disso entra no bloco de memória física (`physical_layout`) e no
//! alocador de frames; para o kernel alcançá-la pelo endereço físico, o
//! boot estende o mesmo mapa logo depois do alocador: uma PD por GB de
//! [4 GB, topo da RAM), em frames do PFN, com páginas de 2 MB de
//! supervisor, RW e NX (as mesmas entradas do stage2) nas entradas 4 em
//! diante da PDPT do mapa direto. A faixa inteira até o topo da RAM, arredondado a 2 MB,
//! fica mapeada, como a de baixo (que também cobre firmware e MMIO). A PDPT
//! é a mesma em toda raiz (a entrada DIRECT_MAP_PML4_INDEX é permanente),
//! então as PDs novas valem em todo espaço de endereçamento; nenhuma CPU
//! guardou as entradas ausentes, e os processadores secundários ainda não
//! subiram. Só depois disso o `hal::physical` aceita endereços acima de
//! 4 GB (`physical::direct_map_limit`).

use super::{memory_map as map, pfn, physical_layout};
use crate::hal::physical;
use crate::rtl::KernelError;

/// Present | RW | PS (página de 2 MB), como as PDEs do stage2.
const LARGE_PAGE_FLAGS: u64 = 0x83;
const NO_EXECUTE: u64 = 1 << 63;
/// Present | RW, como as entradas da PDPT do stage2.
const TABLE_FLAGS: u64 = 0x3;
const GIGABYTE: u64 = 0x4000_0000;

/// Estende o mapa direto até o topo da RAM do bloco, antes dos
/// processadores secundários. Sem RAM acima de 4 GB, nada muda.
pub fn extend() -> Result<(), KernelError> {
    let top = physical_layout::ranges().last().map_or(0, |range| range.1).next_multiple_of(map::LARGE_PAGE_SIZE);
    if top <= map::BOOT_DIRECT_MAP_LIMIT {
        return Ok(());
    }
    if top > map::PHYSICAL_ADDRESS_LIMIT {
        return Err(KernelError::new("RAM above the direct map slot"));
    }
    for gigabyte in map::BOOT_DIRECT_MAP_LIMIT / GIGABYTE..top.div_ceil(GIGABYTE) {
        // A PD fica abaixo de 4 GB, na parte do mapa que já existe.
        let directory = pfn::alloc_contiguous(1, 1, map::BOOT_DIRECT_MAP_LIMIT / map::PAGE_SIZE - 1, 0, 0);
        if directory == 0 {
            return Err(KernelError::new("no frame for a direct map page directory"));
        }
        physical::zero(directory, map::PAGE_SIZE as usize);
        let base = gigabyte * GIGABYTE;
        for index in 0..512 {
            let address = base + index * map::LARGE_PAGE_SIZE;
            if address >= top {
                break;
            }
            physical::write64(directory + index * 8, address | LARGE_PAGE_FLAGS | NO_EXECUTE);
        }
        physical::write64(map::DIRECT_MAP_PDPT_PHYS + gigabyte * 8, directory | TABLE_FLAGS);
    }
    physical::extend_direct_map(top);
    debug_print!("[mm] mapa direto ate {:#x} ({} MB acima de 4 GB)", top, (top - map::BOOT_DIRECT_MAP_LIMIT) >> 20);
    Ok(())
}
