//! Escolha de endereço para vistas de seção e alocações de usuário.
//!
//! Exclui as faixas ocupadas que o chamador passa (VADs, imagens, vistas) e
//! os mapeamentos reais da árvore de páginas. Na metade de usuário a busca
//! é a do MiFindEmptyAddressRange do NT: primeira faixa livre de baixo para
//! cima a partir de MM_LOWEST_USER_ADDRESS (64 KB), ou de cima para baixo a
//! partir de MM_HIGHEST_VAD_ADDRESS no MEM_TOP_DOWN, sem cursor: uma faixa
//! liberada volta a ser a primeira candidata.

use crate::ntos::mm::{memory_map as map, paging};

/// Faixa ocupada (base, tamanho).
#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub base: u64,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FindOptions {
    pub system_space: bool,
    pub size: u64,
    /// 0 = 64 KB.
    pub alignment: u64,
    /// 0 = livre (o endereço zero nunca é um pedido fixo).
    pub base: u64,
    pub top_down: bool,
    /// Último endereço que a faixa pode cobrir (inclusivo); `None` =
    /// MM_HIGHEST_VAD_ADDRESS.
    pub upper: Option<u64>,
    /// Piso pedido; nunca abaixo de MM_LOWEST_USER_ADDRESS.
    pub minimum: Option<u64>,
}

fn collision(regions: &[Region], base: u128, size: u128) -> Option<(u128, u128)> {
    regions
        .iter()
        .find(|region| base < region.base as u128 + region.size as u128 && base + size > region.base as u128)
        .map(|region| (region.base as u128, region.size as u128))
        .or_else(|| paging::find_mapping(base as u64, size as u64).map(|(found, length)| (found as u128, length as u128)))
}

/// Faixa global de seções do sistema.
fn find_system(options: &FindOptions, regions: &[Region]) -> Result<u64, u32> {
    let size = options.size as u128;
    let alignment = if options.alignment == 0 { 65536 } else { options.alignment } as u128;
    let fixed = options.base != 0;
    let align = |address: u128| address.div_ceil(alignment) * alignment;
    let mut base = align(if fixed { options.base as u128 } else { map::KERNEL_SECTION_BASE as u128 });
    while base >= map::KERNEL_SECTION_BASE as u128 && base + size <= map::KERNEL_SECTION_TOP as u128 {
        match collision(regions, base, size) {
            None => return Ok(base as u64),
            Some(_) if fixed => return Err(0xC000_0018),
            Some((found, length)) => base = align(found + length),
        }
    }
    Err(if fixed { 0xC000_0018 } else { 0xC000_0017 })
}

/// Uma faixa livre da metade de usuário (ou de sistema, com `system_space`).
/// Base fixa: a própria base, ou STATUS_CONFLICTING_ADDRESSES se ela cai
/// fora de [piso, topo] ou colide; sem base: a primeira faixa alinhada que
/// cabe, ou STATUS_NO_MEMORY.
pub fn find(options: &FindOptions, regions: &[Region]) -> Result<u64, u32> {
    if options.system_space {
        return find_system(options, regions);
    }
    let size = options.size as i128;
    let alignment = if options.alignment == 0 { map::ALLOCATION_GRANULARITY } else { options.alignment } as i128;
    let limit = map::HIGHEST_VAD_ADDRESS as i128 + 1;
    let upper = limit.min(options.upper.map_or(limit, |upper| upper as i128 + 1));
    let floor = map::LOWEST_USER_ADDRESS as i128;
    let minimum = options.minimum.map_or(floor, |minimum| (minimum as i128).max(floor));
    let fixed = options.base != 0;
    let floor_to = |value: i128| value.div_euclid(alignment) * alignment;
    let ceil_to = |value: i128| (value + alignment - 1).div_euclid(alignment) * alignment;
    if size <= 0 || size > (1i128 << 53) - 1 {
        return Err(0xC000_001F);
    }
    let mut base = if fixed {
        options.base as i128
    } else if options.top_down {
        floor_to(upper - size)
    } else {
        ceil_to(minimum)
    };
    while base >= minimum && base + size <= upper {
        match collision(regions, base as u128, size as u128) {
            None => return Ok(base as u64),
            Some(_) if fixed => return Err(0xC000_0018),
            Some((found, length)) => {
                base = if options.top_down { floor_to(found as i128 - size) } else { ceil_to(found as i128 + length as i128) };
            }
        }
    }
    Err(if fixed { 0xC000_0018 } else { 0xC000_0017 })
}
