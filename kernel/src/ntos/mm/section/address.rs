//! Escolha de endereço para vistas de seção.
//!
//! Exclui as vistas do provedor e os mapeamentos reais da árvore de páginas.

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
    pub upper: Option<u64>,
    pub minimum: Option<u64>,
    /// Dica do cursor (0 = nenhuma).
    pub start: u64,
    pub wrap: bool,
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

pub fn find(options: &FindOptions, regions: &[Region]) -> Result<u64, u32> {
    if options.system_space {
        return find_system(options, regions);
    }
    let size = options.size as i128;
    let alignment = if options.alignment == 0 { 65536 } else { options.alignment } as i128;
    let limit = map::USER_ADDRESS_LIMIT as i128;
    let upper = limit.min(options.upper.map_or(limit, |upper| upper as i128 + 1));
    // Seções mantêm o piso do bootstrap; VM privada passa seu limite inferior
    // e a árvore real de páginas exclui as VAs de supervisor.
    let minimum = options.minimum.map_or(0x1_0000_0000, |minimum| (minimum as i128).max(0x10000));
    let fixed = options.base != 0;
    let start = if options.start != 0 { options.start as i128 } else { 0 };
    let floor_to = |value: i128| value.div_euclid(alignment) * alignment;
    let ceil_to = |value: i128| (value + alignment - 1).div_euclid(alignment) * alignment;
    let mut base = if fixed {
        options.base as i128
    } else if options.top_down {
        floor_to((if start != 0 { start } else { upper }).min(upper) - size)
    } else {
        ceil_to((if start != 0 { start } else { minimum }).max(minimum))
    };
    if !fixed && base + size > upper && !options.top_down {
        base = ceil_to(minimum);
    }
    if size <= 0 || size > (1i128 << 53) - 1 {
        return Err(0xC000_001F);
    }
    let attempts = if options.wrap && !fixed { 2 } else { 1 };
    for _ in 0..attempts {
        while base >= minimum && base + size <= upper {
            match collision(regions, base as u128, size as u128) {
                None => return Ok(base as u64),
                Some(_) if fixed => return Err(0xC000_0018),
                Some((found, length)) => {
                    base = if options.top_down { floor_to(found as i128 - size) } else { ceil_to(found as i128 + length as i128) };
                }
            }
        }
        // O cursor é só uma dica: esgotar um lado não esconde um intervalo
        // livre do outro lado.
        base = if options.top_down { floor_to(upper - size) } else { ceil_to(minimum) };
    }
    Err(if fixed { 0xC000_0018 } else { 0xC000_0017 })
}
